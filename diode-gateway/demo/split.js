const params = new URLSearchParams(location.search);
const isLocal = location.hostname === "127.0.0.1" || location.hostname === "localhost";
const dev = params.get("mode") === "dev" || (params.get("mode") !== "netns" && isLocal);
document.getElementById("mode-label").textContent = dev ? "Demo localhost" : "Topologi Linux, perlu verifikasi";
document.getElementById("low").src = dev ? "http://127.0.0.1:5000/" : "http://10.10.10.2:5000/";
document.getElementById("high").src = dev ? "http://127.0.0.1:5001/" : "http://10.10.10.3:5001/";
