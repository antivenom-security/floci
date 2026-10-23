package io.github.hectorvent.floci.services.ec2;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.command.ListContainersCmd;
import com.github.dockerjava.api.model.Container;
import com.github.dockerjava.api.model.Info;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.dns.EmbeddedDnsServer;
import io.github.hectorvent.floci.core.common.docker.ContainerBuilder;
import io.github.hectorvent.floci.core.common.docker.ContainerLifecycleManager;
import io.github.hectorvent.floci.core.common.docker.ContainerSpec;
import io.github.hectorvent.floci.core.common.docker.DockerHostResolver;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SecurityGroupFirewallManagerTest {

    @Test
    void helperCarriesTheResolverAndHostsItsWorkloadsUse() {
        ContainerSpec helper = helperSpec(Optional.empty());

        assertTrue(helper.dnsServers().contains("172.18.0.2"), "the helper uses Floci's DNS");
        assertTrue(helper.extraHosts().contains("host.docker.internal:host-gateway"),
                "the helper resolves host.docker.internal");
        assertEquals(Map.of("net.netfilter.nf_conntrack_acct", "1"), helper.linuxOptions().sysctls(),
                "observed flow logs, the default with enforcement on, need conntrack accounting");
    }

    /** The sysctl fails container creation where nf_conntrack is not loaded, so only flow logs ask for it. */
    @Test
    void helperSetsNoSysctlUnlessFlowLogsAreObserved() {
        assertEquals(Map.of(), helperSpec(Optional.of("synthetic")).linuxOptions().sysctls());
    }

    private static ContainerSpec helperSpec(Optional<String> flowLogsMode) {
        EmulatorConfig config = mock(EmulatorConfig.class, RETURNS_DEEP_STUBS);
        when(config.services().ec2().flowLogs().mode()).thenReturn(flowLogsMode);
        when(config.network().securityGroupEnforcement().enabled()).thenReturn(true);
        when(config.network().securityGroupEnforcement().helperImage()).thenReturn("floci/network-helper:local");
        when(config.docker().resourceNamespace()).thenReturn(Optional.empty());
        when(config.docker().imageRegistryBase()).thenReturn(Optional.empty());
        DockerClient dockerClient = mock(DockerClient.class, RETURNS_DEEP_STUBS);
        Info linux = mock(Info.class);
        when(linux.getOsType()).thenReturn("linux");
        when(dockerClient.infoCmd().exec()).thenReturn(linux);
        when(dockerClient.inspectImageCmd(anyString()).exec()).thenReturn(null);
        DockerHostResolver dockerHostResolver = mock(DockerHostResolver.class);
        when(dockerHostResolver.isLinuxHost()).thenReturn(true);
        EmbeddedDnsServer embeddedDnsServer = mock(EmbeddedDnsServer.class);
        when(embeddedDnsServer.getServerIp()).thenReturn(Optional.of("172.18.0.2"));
        ContainerLifecycleManager lifecycleManager = mock(ContainerLifecycleManager.class);
        when(lifecycleManager.createAndStart(any())).thenThrow(new IllegalStateException("stop after the spec"));
        SecurityGroupFirewallManager manager = new SecurityGroupFirewallManager(dockerClient,
                new ContainerBuilder(config, dockerHostResolver, embeddedDnsServer), lifecycleManager, config,
                embeddedDnsServer);

        assertThrows(IllegalStateException.class, () -> manager.createNamespace("ec2", "i-1", "000000000000",
                "us-east-1", Optional.empty(), Map.of()));

        ArgumentCaptor<ContainerSpec> helper = ArgumentCaptor.forClass(ContainerSpec.class);
        verify(lifecycleManager).createAndStart(helper.capture());
        return helper.getValue();
    }

    @Test
    void onlyFlocisDnsIsExemptFromTheSecurityGroups() {
        EmbeddedDnsServer embeddedDnsServer = mock(EmbeddedDnsServer.class);
        when(embeddedDnsServer.getServerIp()).thenReturn(Optional.of("172.18.0.2"));
        EmulatorConfig config = mock(EmulatorConfig.class, RETURNS_DEEP_STUBS);
        when(config.dns().containerFallbackServers()).thenReturn(List.of("8.8.8.8", "8.8.4.4"));
        SecurityGroupFirewallManager manager = new SecurityGroupFirewallManager(mock(DockerClient.class),
                mock(ContainerBuilder.class), mock(ContainerLifecycleManager.class), config, embeddedDnsServer);

        assertEquals(List.of("172.18.0.2"), manager.vpcResolvers());

        when(embeddedDnsServer.getServerIp()).thenReturn(Optional.empty());
        assertEquals(List.of(), manager.vpcResolvers());
    }
    @Test
    void survivingEcsHelpersAreFoundUnderTheNewAndLegacyLabelsAndRemovedOnlyWhenTheirOwnersAgree() {
        EmulatorConfig config = mock(EmulatorConfig.class, RETURNS_DEEP_STUBS);
        when(config.network().securityGroupEnforcement().enabled()).thenReturn(true);
        when(config.port()).thenReturn(4566);
        when(config.docker().resourceNamespace()).thenReturn(Optional.empty());
        DockerClient dockerClient = mock(DockerClient.class);
        ListContainersCmd listCmd = mock(ListContainersCmd.class, RETURNS_SELF);
        when(dockerClient.listContainersCmd()).thenReturn(listCmd);
        when(listCmd.exec()).thenReturn(List.of());
        ListContainersCmd byNewKeys = mock(ListContainersCmd.class);
        ListContainersCmd byLegacyKeys = mock(ListContainersCmd.class);
        when(listCmd.withLabelFilter(Map.of("io.floci.security-group.helper", "true"))).thenReturn(byNewKeys);
        when(listCmd.withLabelFilter(Map.of("floci.security-group-helper", "true"))).thenReturn(byLegacyKeys);
        Container newOnly = exitedEcsHelper("new-only",
                Map.of("io.floci.security-group.helper", "true", "io.floci.owner", "4566"));
        Container legacyOnly = exitedEcsHelper("legacy-only",
                Map.of("floci.security-group-helper", "true", "floci_owner_port", "4566"));
        Container both = exitedEcsHelper("both", Map.of(
                "io.floci.security-group.helper", "true", "io.floci.owner", "4566",
                "floci.security-group-helper", "true", "floci_owner_port", "4566"));
        Container disagreeing = exitedEcsHelper("disagreeing", Map.of(
                "io.floci.security-group.helper", "true", "io.floci.owner", "4566",
                "floci.security-group-helper", "true", "floci_owner_port", "4567"));
        when(byNewKeys.exec()).thenReturn(List.of(newOnly, both, disagreeing));
        when(byLegacyKeys.exec()).thenReturn(List.of(legacyOnly, both, disagreeing));
        ContainerLifecycleManager lifecycleManager = mock(ContainerLifecycleManager.class);
        SecurityGroupFirewallManager manager = new SecurityGroupFirewallManager(dockerClient,
                mock(ContainerBuilder.class), lifecycleManager, config, mock(EmbeddedDnsServer.class));

        manager.quarantineSurvivingNamespaces();

        verify(lifecycleManager).removeIfExists("new-only");
        verify(lifecycleManager).removeIfExists("legacy-only");
        verify(lifecycleManager).removeIfExists("both");
        verify(lifecycleManager, never()).removeIfExists("disagreeing");
    }

    private static Container exitedEcsHelper(String id, Map<String, String> ownerLabels) {
        Map<String, String> labels = new HashMap<>(ownerLabels);
        labels.put("io.floci.service", "ecs");
        Container container = mock(Container.class);
        when(container.getId()).thenReturn(id);
        when(container.getState()).thenReturn("exited");
        when(container.getLabels()).thenReturn(labels);
        return container;
    }
}
