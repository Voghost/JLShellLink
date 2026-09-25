package com.jlshell.link.server.spring;

import com.jlshell.link.server.LinkServer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Import this configuration from Website after supplying the Website-backed LinkServer bean. */
@Configuration(proxyBeanMethods = false)
public class LinkServerSpringConfiguration {
    @Bean
    public LinkServerSmartLifecycle linkServerSmartLifecycle(LinkServer linkServer) {
        return new LinkServerSmartLifecycle(linkServer);
    }
}
