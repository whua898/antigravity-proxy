package com.antigravity.agent;

import java.io.File;
import java.io.IOException;
import java.lang.instrument.Instrumentation;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ProxyAgent {

    private static String proxyHost = "127.0.0.1";
    private static int proxyPort = 0;
    private static String proxyType = "socks";

    public static void premain(String agentArgs, Instrumentation inst) {
        System.out.println("[AntigravityAgent] Initializing...");

        // 1. 找到 config.json 的路径
        // 假设 config.json 与 agent.jar 在同一目录
        String configPath = findConfigPath();
        if (configPath == null) {
            System.err.println("[AntigravityAgent] Error: config.json not found.");
            // 即使找不到配置，也设置一个默认的代理选择器，避免完全失效
            // 但这里我们先简单处理，找不到就退出
            return;
        }

        // 2. 解析 config.json
        try {
            String content = new String(Files.readAllBytes(Paths.get(configPath)));
            parseConfig(content);
        } catch (IOException e) {
            System.err.println("[AntigravityAgent] Error reading config.json: " + e.getMessage());
            return;
        }

        // 3. 设置自定义的 ProxySelector
        ProxySelector.setDefault(new ProxySelector() {
            @Override
            public List<Proxy> select(URI uri) {
                // 如果端口是 0，尝试自动探测（简化版，实际应更复杂）
                if (proxyPort == 0) {
                    // 在 Java Agent 中探测端口比较麻烦，暂时硬编码
                    proxyPort = 7890;
                }

                Proxy.Type type = proxyType.equalsIgnoreCase("socks") ? Proxy.Type.SOCKS : Proxy.Type.HTTP;
                Proxy proxy = new Proxy(type, new InetSocketAddress(proxyHost, proxyPort));
                return Collections.singletonList(proxy);
            }

            @Override
            public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {
                System.err.println("[AntigravityAgent] Connection to proxy failed: " + ioe.getMessage());
                // 这里可以实现故障自愈逻辑，例如重新探测端口
            }
        });

        System.out.println("[AntigravityAgent] ProxySelector set to: " + proxyType.toUpperCase() + " " + proxyHost + ":" + proxyPort);
    }

    private static String findConfigPath() {
        try {
            // 获取 agent.jar 的路径
            String jarPath = ProxyAgent.class
                    .getProtectionDomain()
                    .getCodeSource()
                    .getLocation()
                    .toURI()
                    .getPath();
            File jarFile = new File(jarPath);
            File configFile = new File(jarFile.getParent(), "config.json");
            if (configFile.exists()) {
                return configFile.getAbsolutePath();
            }
        } catch (Exception e) {
            System.err.println("[AntigravityAgent] Error finding agent path: " + e.getMessage());
        }
        return null;
    }

    private static void parseConfig(String content) {
        // 简单的 JSON 解析，避免引入外部库
        Pattern hostPattern = Pattern.compile("\"host\"\\s*:\\s*\"(.*?)\"");
        Pattern portPattern = Pattern.compile("\"port\"\\s*:\\s*(\\d+)");
        Pattern typePattern = Pattern.compile("\"type\"\\s*:\\s*\"(.*?)\"");

        Matcher hostMatcher = hostPattern.matcher(content);
        if (hostMatcher.find()) {
            proxyHost = hostMatcher.group(1);
        }

        Matcher portMatcher = portPattern.matcher(content);
        if (portMatcher.find()) {
            proxyPort = Integer.parseInt(portMatcher.group(1));
        }

        Matcher typeMatcher = typePattern.matcher(content);
        if (typeMatcher.find()) {
            proxyType = typeMatcher.group(1);
        }
    }
}
