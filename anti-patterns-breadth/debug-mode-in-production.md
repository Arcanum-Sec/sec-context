# Debug Mode in Production


```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Debug mode enabled in production
// ========================================

// Mistake 1: Hardcoded debug flag
CONSTANT DEBUG = TRUE  // Never changes between environments

FUNCTION start_application():
    app.config.debug = TRUE
    app.config.show_stack_traces = TRUE
    app.config.enable_profiler = TRUE

    // Exposes: full stack traces, variable values, file paths, database queries
    app.run()
END FUNCTION

// Mistake 2: Debug routes left enabled
app.route("/debug/env", show_environment_variables)
app.route("/debug/config", show_all_config)
app.route("/debug/sql", run_arbitrary_sql)  // Catastrophic!

// Mistake 3: Development tools in production bundle
// package.json or requirements with dev dependencies in production
// React DevTools, Vue DevTools, Django Debug Toolbar exposed

// ========================================
// GOOD: Environment-based configuration
// ========================================

FUNCTION start_application():
    environment = get_environment_variable("APP_ENV", "production")

    IF environment == "production":
        app.config.debug = FALSE
        app.config.show_stack_traces = FALSE
        app.config.enable_profiler = FALSE

        // Ensure debug routes are not registered
        disable_debug_routes()

    ELSE IF environment == "development":
        // Only enable debug in development
        app.config.debug = TRUE
        register_debug_routes()
    END IF

    app.run()
END FUNCTION

FUNCTION disable_debug_routes():
    // Explicitly remove or disable debug endpoints
    // Better: Don't register them in production at all

    debug_routes = ["/debug/*", "/test/*", "/__debug__/*", "/profiler/*"]
    FOR route IN debug_routes:
        app.remove_route(route)
    END FOR
END FUNCTION

// Build process should exclude dev dependencies
// package.json: use --production flag
// requirements.txt: separate dev-requirements.txt
// Dockerfile: multi-stage build without dev tools
```
