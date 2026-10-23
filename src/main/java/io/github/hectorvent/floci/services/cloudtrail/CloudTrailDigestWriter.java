package io.github.hectorvent.floci.services.cloudtrail;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsRegions;
import io.github.hectorvent.floci.core.common.Digests;
import io.github.hectorvent.floci.core.common.RequestScopes;
import io.github.hectorvent.floci.core.storage.AccountAwareStorageBackend;
import io.github.hectorvent.floci.core.storage.StorageFactory;
import io.github.hectorvent.floci.services.cloudtrail.model.Trail;
import io.github.hectorvent.floci.services.s3.S3Service;
import io.quarkus.runtime.ShutdownEvent;
import io.quarkus.runtime.Startup;
import io.quarkus.runtime.annotations.RegisterForReflection;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Writes the digest files of trails with log file validation, as AWS's custom validation guide
 * describes: every interval, per trail and region, even when no log file was delivered, chained to the
 * previous digest and signed with SHA256withRSA by the region's key over
 * {@code endTime\nbucket/key\nhex(sha256(digest))\npreviousSignature}. The signature travels in the
 * object's {@code signature} metadata. {@code ListPublicKeys} serves the keys.
 */
@Startup
@ApplicationScoped
public class CloudTrailDigestWriter {

    private static final Logger LOG = Logger.getLogger(CloudTrailDigestWriter.class);
    static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String HASH_ALGORITHM = "SHA-256";
    private static final Duration KEY_VALIDITY = Duration.ofDays(365);
    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'")
            .withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter KEY_TIME = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'")
            .withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter PATH_DATE = DateTimeFormatter.ofPattern("yyyy/MM/dd")
            .withZone(ZoneOffset.UTC);

    private final EmulatorConfig config;
    private final CloudTrailService cloudTrailService;
    private final S3Service s3Service;
    private final ObjectMapper mapper;
    private final AccountAwareStorageBackend<DigestKey> keys;
    private final Map<ChainKey, Chain> chains = new ConcurrentHashMap<>();
    private final Map<ChainKey, List<LogFile>> pending = new ConcurrentHashMap<>();

    private ScheduledExecutorService executor;

    @Inject
    public CloudTrailDigestWriter(EmulatorConfig config, CloudTrailService cloudTrailService, S3Service s3Service,
                                  ObjectMapper mapper, StorageFactory storageFactory) {
        this.config = config;
        this.cloudTrailService = cloudTrailService;
        this.s3Service = s3Service;
        this.mapper = mapper;
        this.keys = storageFactory.create("cloudtrail", "cloudtrail-digest-keys.json",
                new TypeReference<Map<String, DigestKey>>() {});
    }

    @PostConstruct
    void start() {
        if (!config.services().cloudtrail().enabled()) {
            return;
        }
        int interval = Math.max(1, config.services().cloudtrail().digestIntervalSeconds());
        executor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "cloudtrail-digest-writer");
            t.setDaemon(true);
            return t;
        });
        executor.scheduleAtFixedRate(this::writeDigests, interval, interval, TimeUnit.SECONDS);
    }

    void stop(@Observes ShutdownEvent event) {
        if (executor != null) {
            executor.shutdownNow();
            executor = null;
        }
    }

    void logDelivered(CloudTrailService.TrailKey key, String bucket, String objectKey, byte[] json,
                      List<ObjectNode> records) {
        String oldest = null;
        String newest = null;
        for (ObjectNode record : records) {
            String time = record.path("eventTime").asText();
            oldest = oldest == null || time.compareTo(oldest) < 0 ? time : oldest;
            newest = newest == null || time.compareTo(newest) > 0 ? time : newest;
        }
        LogFile file = new LogFile(bucket, objectKey, Digests.sha256Hex(json), oldest, newest);
        ChainKey chainKey = new ChainKey(new TrailId(key.accountId(), key.region(), key.trailName()),
                key.eventRegion());
        pending.compute(chainKey, (ignored, files) -> {
            List<LogFile> updated = files == null ? new ArrayList<>() : files;
            updated.add(file);
            return updated;
        });
    }

    public void writeDigests() {
        Instant end = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Set<TrailId> active = new HashSet<>();
        for (AccountAwareStorageBackend.AccountEntry<CloudTrailEntry> stored : cloudTrailService.loggingTrails()) {
            String account = stored.accountId();
            CloudTrailEntry entry = stored.value();
            Trail trail = entry.trail();
            if (!trail.logFileValidationEnabled()) {
                continue;
            }
            TrailId id = new TrailId(account, trail.homeRegion(), trail.name());
            active.add(id);
            Set<String> regions = new LinkedHashSet<>(trail.isMultiRegionTrail()
                    ? AwsRegions.advertised(AwsRegions.partitionFor(trail.homeRegion())) : List.of(trail.homeRegion()));
            for (ChainKey key : pending.keySet()) {
                if (key.trail().equals(id)) {
                    regions.add(key.region());
                }
            }
            for (String region : regions) {
                try {
                    RequestScopes.runAs(account, () -> writeDigest(id, trail, entry.startLoggingTime(), region, end));
                    cloudTrailService.updateChannels(account, trail.homeRegion(), trail.name(),
                            c -> c.digest(end.toEpochMilli(), null));
                } catch (RuntimeException e) {
                    LOG.warnv(e, "CloudTrail digest delivery failed for trail {0} in {1}", trail.name(), region);
                    String error = e.getMessage();
                    cloudTrailService.updateChannels(account, trail.homeRegion(), trail.name(),
                            c -> c.digest(c.digestDeliveryTime(), error));
                }
            }
        }
        chains.keySet().removeIf(key -> !active.contains(key.trail()));
        pending.keySet().removeIf(key -> !active.contains(key.trail()));
    }

    private void writeDigest(TrailId id, Trail trail, Long startLoggingTime, String region, Instant end) {
        String account = id.accountId();
        ChainKey chainKey = new ChainKey(id, region);
        Chain stored = chains.get(chainKey);
        Chain previous = stored != null && Objects.equals(stored.startLoggingTime(), startLoggingTime) ? stored : null;
        List<LogFile> files = drainPending(chainKey);
        String bucket = trail.s3BucketName();
        String objectKey = CloudTrailService.keyPrefix(trail.s3KeyPrefix()) + "AWSLogs/" + account
                + "/CloudTrail-Digest/" + region + "/" + PATH_DATE.format(end) + "/" + account
                + "_CloudTrail-Digest_" + region + "_" + trail.name() + "_" + trail.homeRegion() + "_"
                + KEY_TIME.format(end) + ".json.gz";
        Instant start = previous != null ? previous.end()
                : Instant.ofEpochMilli(startLoggingTime != null ? startLoggingTime : end.toEpochMilli())
                .truncatedTo(ChronoUnit.SECONDS);
        DigestKey key = key(account, region);
        try {
            byte[] json = mapper.writeValueAsBytes(digest(account, start, end, bucket, objectKey, key, previous, files));
            String hash = Digests.sha256Hex(json);
            String previousSignature = previous == null ? "null" : previous.signature();
            String signature = sign(key, TIME.format(end) + "\n" + bucket + "/" + objectKey + "\n" + hash + "\n"
                    + previousSignature);
            s3Service.putObject(bucket, objectKey, CloudTrailLogWriter.gzip(json), "application/x-gzip",
                    Map.of("signature", signature, "signature-algorithm", SIGNATURE_ALGORITHM));
            chains.put(chainKey, new Chain(startLoggingTime, end, bucket, objectKey, signature, hash));
        } catch (IOException | GeneralSecurityException | RuntimeException e) {
            pending.compute(chainKey, (ignored, newer) -> {
                List<LogFile> restored = new ArrayList<>(files);
                if (newer != null) {
                    restored.addAll(newer);
                }
                return restored.isEmpty() ? null : restored;
            });
            throw e instanceof RuntimeException runtime ? runtime : new IllegalStateException(e.getMessage(), e);
        }
    }

    private ObjectNode digest(String account, Instant start, Instant end, String bucket, String objectKey,
                              DigestKey key, Chain previous, List<LogFile> files) {
        ObjectNode digest = mapper.createObjectNode();
        digest.put("awsAccountId", account);
        digest.put("digestStartTime", TIME.format(start));
        digest.put("digestEndTime", TIME.format(end));
        digest.put("digestS3Bucket", bucket);
        digest.put("digestS3Object", objectKey);
        digest.put("digestPublicKeyFingerprint", key.fingerprint());
        digest.put("digestSignatureAlgorithm", SIGNATURE_ALGORITHM);
        digest.put("newestEventTime", files.stream().map(LogFile::newest).max(String::compareTo).orElse(null));
        digest.put("oldestEventTime", files.stream().map(LogFile::oldest).min(String::compareTo).orElse(null));
        digest.put("previousDigestS3Bucket", previous == null ? null : previous.bucket());
        digest.put("previousDigestS3Object", previous == null ? null : previous.key());
        digest.put("previousDigestHashValue", previous == null ? null : previous.hash());
        digest.put("previousDigestHashAlgorithm", previous == null ? null : HASH_ALGORITHM);
        digest.put("previousDigestSignature", previous == null ? null : previous.signature());
        ArrayNode logFiles = digest.putArray("logFiles");
        for (LogFile file : files) {
            logFiles.addObject()
                    .put("s3Bucket", file.bucket())
                    .put("s3Object", file.key())
                    .put("hashValue", file.hash())
                    .put("hashAlgorithm", HASH_ALGORITHM)
                    .put("newestEventTime", file.newest())
                    .put("oldestEventTime", file.oldest());
        }
        return digest;
    }

    private List<LogFile> drainPending(ChainKey key) {
        List<LogFile> files = pending.remove(key);
        return files == null ? List.of() : files;
    }

    /** The account's public keys for {@code region} valid at some point between {@code start} and {@code end}. */
    public List<DigestKey> publicKeys(String account, String region, Instant start, Instant end) {
        return regionKeys(account, region).stream()
                .filter(key -> (end == null || key.validityStart() <= end.toEpochMilli())
                        && (start == null || key.validityEnd() >= start.toEpochMilli()))
                .toList();
    }

    /** The region's newest key still within its validity, rotating to a new one once it lapses. */
    private synchronized DigestKey key(String account, String region) {
        long now = System.currentTimeMillis();
        return regionKeys(account, region).stream()
                .filter(key -> key.validityEnd() > now)
                .max(Comparator.comparingLong(DigestKey::validityStart))
                .orElseGet(() -> {
                    DigestKey created = generateKey();
                    keys.putForAccount(account, region + "/" + created.fingerprint(), created);
                    return created;
                });
    }

    private List<DigestKey> regionKeys(String account, String region) {
        return keys.scanAllAccountEntries(key -> key.startsWith(region + "/")).stream()
                .filter(entry -> entry.accountId().equals(account))
                .map(AccountAwareStorageBackend.AccountEntry::value)
                .toList();
    }

    private static DigestKey generateKey() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair pair = generator.generateKeyPair();
            byte[] pkcs1 = SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded())
                    .parsePublicKey().getEncoded();
            long now = System.currentTimeMillis();
            return new DigestKey(Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()),
                    Base64.getEncoder().encodeToString(pkcs1),
                    HexFormat.of().formatHex(MessageDigest.getInstance("MD5").digest(pkcs1)),
                    now, now + KEY_VALIDITY.toMillis());
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException("Failed to generate a CloudTrail digest key", e);
        }
    }

    private static String sign(DigestKey key, String data) throws GeneralSecurityException {
        PrivateKey privateKey = KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(key.privateKey())));
        Signature signer = Signature.getInstance(SIGNATURE_ALGORITHM);
        signer.initSign(privateKey);
        signer.update(data.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(signer.sign());
    }

    /** A region's digest signing key: PKCS#8 private and DER PKCS#1 public keys, base64. */
    @RegisterForReflection
    public record DigestKey(String privateKey, String publicKey, String fingerprint,
                            long validityStart, long validityEnd) {
    }

    private record TrailId(String accountId, String homeRegion, String name) {
    }

    private record ChainKey(TrailId trail, String region) {
    }

    private record Chain(Long startLoggingTime, Instant end, String bucket, String key, String signature,
                         String hash) {
    }

    private record LogFile(String bucket, String key, String hash, String oldest, String newest) {
    }
}
