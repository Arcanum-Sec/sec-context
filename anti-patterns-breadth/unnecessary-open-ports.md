# Unnecessary Open Ports and Services


```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Unnecessary services and ports exposed
// ========================================

// Mistake 1: Debug/development ports left open in production
app.listen(3000)                    // Main app
debug_server.listen(9229)           // Node.js debugger - remote code execution!
profiler.listen(8888)               // Profiler endpoint
metrics_internal.listen(9090)       // Prometheus metrics with sensitive data

// Mistake 2: Database ports exposed to network
// MongoDB on 27017, MySQL on 3306, PostgreSQL on 5432
// Without authentication or bound to 0.0.0.0

// Mistake 3: Management interfaces on public ports
redis.config.bind = "0.0.0.0"       // Redis exposed to network
elasticsearch_http = TRUE            // ES HTTP API exposed

// Mistake 4: All services in one container/server without isolation

// ========================================
// GOOD: Minimal attack surface
// ========================================

// Principle: Only expose what's necessary for the service to function

FUNCTION configure_server():
    // Main application - public facing
    app.listen({
        port: 443,
        host: "0.0.0.0"  // Must be accessible
    })

    // Health check - internal only
    health_server.listen({
        port: 8080,
        host: "127.0.0.1"  // Only accessible from localhost/internal
    })

    // Metrics - internal only, with authentication
    metrics_server.listen({
        port: 9090,
        host: "127.0.0.1",
        middleware: [basic_auth_middleware]
    })

    // NEVER start debug servers in production
    IF environment == "production":
        // Debug features should not exist in production code
        // Or be explicitly disabled
        disable_debug_endpoints()
    END IF
END FUNCTION

// Database configuration - never expose to network
FUNCTION configure_database():
    // Option 1: Unix socket (local only)
    database.connect({
        socket: "/var/run/postgresql/.s.PGSQL.5432"
    })

    // Option 2: Localhost binding
    database.connect({
        host: "127.0.0.1",
        port: 5432
    })

    // Option 3: Private network with firewall rules
    database.connect({
        host: "10.0.1.50",  // Internal IP, firewalled from internet
        port: 5432,
        ssl: TRUE
    })
END FUNCTION

// Container/service isolation
// Dockerfile example (pseudocode):
// EXPOSE 443           # Only expose necessary port
// USER nonroot         # Don't run as root
// Don't include: debuggers, profilers, shells, package managers

FUNCTION verify_minimal_ports():
    // Startup check - fail if unexpected ports are listening

    expected_ports = {
        443: "application",
        8080: "health_check"
    }

    listening_ports = get_listening_ports()

    FOR port IN listening_ports:
        IF port NOT IN expected_ports:
            log.error("Unexpected port listening", {port: port})

            IF environment == "production":
                THROW SecurityError("Unexpected port " + port + " listening")
            END IF
        END IF
    END FOR
END FUNCTION

// Firewall configuration (pseudocode for iptables/security groups)
firewall_rules = {
    inbound: [
        {port: 443, source: "0.0.0.0/0", description: "HTTPS"},
        {port: 80, source: "0.0.0.0/0", description: "HTTP (redirect to HTTPS)"},
        {port: 22, source: "10.0.0.0/8", description: "SSH from internal only"}
    ],
    outbound: [
        {port: 443, dest: "0.0.0.0/0", description: "HTTPS APIs"},
        {port: 53, dest: "10.0.0.1", description: "DNS to internal resolver"}
    ],
    default: "deny"
}

// Service mesh / network policies for Kubernetes
network_policy = {
    ingress: [
        {from: "ingress-controller", ports: [8080]}
    ],
    egress: [
        {to: "database", ports: [5432]},
        {to: "cache", ports: [6379]}
    ]
}
```

---
