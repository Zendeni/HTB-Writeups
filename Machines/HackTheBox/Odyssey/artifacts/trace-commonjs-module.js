function(modulePath) {
    var result = {path: modulePath, state: "pending", trace: [], exports: {}, invocations: {}};

    function render(value) {
        try {
            if (value === null) return "null";
            if (value === undefined) return "undefined";
            if (typeof value === "string") return value;
            if (typeof value === "number" || typeof value === "boolean") return String(value);
            if (typeof value === "function") return String(value).slice(0, 12000);
            return JSON.stringify(value).slice(0, 12000);
        } catch (error) {
            try { return String(value); } catch (ignored) { return "<unrenderable>"; }
        }
    }

    function proxyFor(path) {
        var target = function() {};
        var proxy = new Proxy(target, {
            get: function(_target, property) {
                if (property === Symbol.toPrimitive) {
                    return function() { return "[proxy " + path + "]"; };
                }
                if (property === "then") return undefined;
                if (property === "toJSON") return undefined;
                result.trace.push({op: "get", path: path + "." + String(property)});
                return proxyFor(path + "." + String(property));
            },
            apply: function(_target, _thisArg, args) {
                result.trace.push({op: "call", path: path, args: args.map(render)});
                if (path.slice(-5) === ".post" && args[0] === "/admin/templates/:id/render") {
                    var handler = args[args.length - 1];
                    if (typeof handler === "function") {
                        try {
                            var fakeRequest = {
                                params: {id: "legacy-codesign-v1"},
                                body: {body: "TRACE-CONTROL", overrides: {}},
                                session: {userId: 1, userHandle: "admin", userRole: "Administrator"},
                                ip: "127.0.0.1",
                                url: "/admin/templates/legacy-codesign-v1/render"
                            };
                            var invocation = handler(fakeRequest, proxyFor("response"), function() {});
                            result.trace.push({op: "handler-invoke", path: args[0], result: render(invocation)});
                        } catch (error) {
                            result.trace.push({op: "handler-error", path: args[0], error: String(error)});
                        }
                    }
                }
                return proxyFor(path + "()");
            },
            construct: function(_target, args) {
                result.trace.push({op: "construct", path: path, args: args.map(render)});
                return proxyFor("new " + path);
            }
        });
        return proxy;
    }

    globalThis.exports = {};
    globalThis.module = {exports: globalThis.exports};
    globalThis.require = function(name) {
        result.trace.push({op: "require", path: String(name)});
        return proxyFor("require(" + String(name) + ")");
    };
    globalThis.process = {
        env: new Proxy({}, {
            get: function(_target, property) {
                result.trace.push({op: "env", path: String(property)});
                return undefined;
            }
        }),
        cwd: function() { result.trace.push({op: "process.cwd"}); return "/"; },
        on: function() {},
        once: function() {},
        exit: function(code) { result.trace.push({op: "process.exit", args: [String(code)]}); }
    };
    globalThis.console = {
        log: function() {}, error: function() {}, warn: function() {}, info: function() {}
    };
    globalThis.Buffer = proxyFor("Buffer");
    globalThis.setTimeout = function(callback) { return callback(); };
    globalThis.setInterval = function() { return 0; };
    globalThis.clearTimeout = function() {};
    globalThis.clearInterval = function() {};
    globalThis.__dirname = modulePath.slice(0, modulePath.lastIndexOf("/"));
    globalThis.__filename = modulePath;

    import(modulePath).then(
        function(importedModule) {
            result.state = "ok";
            result.esExports = Object.keys(importedModule);
            var commonExports = globalThis.module.exports;
            result.commonType = typeof commonExports;
            if (commonExports && (typeof commonExports === "object" || typeof commonExports === "function")) {
                Object.keys(commonExports).forEach(function(key) {
                    result.exports[key] = render(commonExports[key]);
                });
                if (typeof commonExports === "function") result.exports.default = render(commonExports);
                Object.keys(commonExports).forEach(function(key) {
                    if (typeof commonExports[key] !== "function") return;
                    try {
                        if (key === "renderPipeline") {
                            result.invocations[key] = render(commonExports[key]({
                                templateId: "trace",
                                body: "TRACE-CONTROL",
                                request: {},
                                officer: {},
                                pipeline: {defaults: {}},
                                artifact: {lineage: []},
                                overrides: {},
                                jobDir: "/tmp/aegis-trace-job"
                            }));
                        } else {
                            result.invocations[key] = render(commonExports[key]());
                        }
                    } catch (error) {
                        result.invocations[key] = "ERROR: " + String(error);
                    }
                });
                if (typeof commonExports === "function") {
                    try { result.invocations.default = render(commonExports()); }
                    catch (error) { result.invocations.default = "ERROR: " + String(error); }
                }
            } else {
                result.exports.default = render(commonExports);
            }
        },
        function(error) {
            result.state = "error";
            result.error = String(error);
            result.properties = {};
            Object.getOwnPropertyNames(error).forEach(function(name) {
                try { result.properties[name] = String(error[name]); }
                catch (ignored) { result.properties[name] = "<unreadable>"; }
            });
        }
    );

    return result;
}
