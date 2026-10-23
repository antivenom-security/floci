package io.github.hectorvent.floci.core.common.docker;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.command.BuildImageResultCallback;
import com.github.dockerjava.api.command.InspectImageResponse;
import com.github.dockerjava.api.exception.NotFoundException;
import com.github.dockerjava.api.model.ContainerConfig;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;

/**
 * Builds a Floci-recipe helper image in the workload daemon the first time something needs it,
 * instead of trying to pull an image that only exists as a Dockerfile checked into Floci itself.
 * Security-group enforcement is the caller today; this exists as a shared utility because a second
 * one is coming (an ECS task-role credentials proxy needs the same image), and the alternative was
 * a verbatim copy of the build alongside the original. The Dockerfile-to-image build handling, and
 * the guard that only builds when the caller is still pointed at Floci's own default, live here.
 */
public final class LocallyBuiltHelperImage {

    private static final String RECIPE_LABEL = "io.floci.helper-recipe";

    private LocallyBuiltHelperImage() {
    }

    /**
     * @param configuredImage the image the caller is actually configured to use
     * @param defaultImage the caller's own built-in default; a caller pointed anywhere else is
     *        responsible for that image being pullable, so nothing is built for it here
     * @param dockerfileResourcePath classpath location of the Dockerfile to build, e.g.
     *        {@code "/docker/network-helper.Dockerfile"}
     */
    public static synchronized void ensureBuilt(DockerClient dockerClient, ContainerBuilder containerBuilder,
                                                String configuredImage, String defaultImage,
                                                String dockerfileResourcePath) {
        if (!defaultImage.equals(configuredImage)) {
            return;
        }
        String image = containerBuilder.resolveImage(configuredImage);
        try (InputStream dockerfile = LocallyBuiltHelperImage.class.getResourceAsStream(dockerfileResourcePath)) {
            if (dockerfile == null) {
                throw new IllegalStateException("Floci helper Dockerfile is missing: " + dockerfileResourcePath);
            }
            byte[] content = dockerfile.readAllBytes();
            String recipe = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(content));
            try {
                InspectImageResponse existing = dockerClient.inspectImageCmd(image).exec();
                ContainerConfig existingConfig = existing == null ? null : existing.getConfig();
                Map<String, String> labels = existingConfig == null || existingConfig.getLabels() == null
                        ? null : existingConfig.getLabels();
                // A tag built from an older recipe is rebuilt, so a changed Dockerfile reaches daemons that cached it.
                if (existingConfig == null || (labels != null && recipe.equals(labels.get(RECIPE_LABEL)))) {
                    return;
                }
            } catch (NotFoundException missing) {
                // Build the versioned Floci recipe in the daemon used for workloads.
            }
            ByteArrayOutputStream archive = new ByteArrayOutputStream(content.length + 1024);
            try (TarArchiveOutputStream tar = new TarArchiveOutputStream(archive)) {
                TarArchiveEntry entry = new TarArchiveEntry("Dockerfile");
                entry.setSize(content.length);
                tar.putArchiveEntry(entry);
                tar.write(content);
                tar.closeArchiveEntry();
            }
            try (BuildImageResultCallback callback = new BuildImageResultCallback()) {
                String built = dockerClient.buildImageCmd(new ByteArrayInputStream(archive.toByteArray()))
                        .withTags(Set.of(image)).withLabels(Map.of(RECIPE_LABEL, recipe))
                        .exec(callback).awaitImageId();
                if (built == null || built.isBlank()) {
                    throw new IllegalStateException("Docker did not build the Floci helper image: " + image);
                }
            }
        } catch (IOException | NoSuchAlgorithmException e) {
            throw new IllegalStateException("Cannot build the Floci helper image: " + image, e);
        }
    }
}
