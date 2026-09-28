"use strict";

const message = document.getElementById("message");
async function api(path, method = "GET", body, authenticated = false) {
    const headers = { "Content-Type": "application/json" };
    if (authenticated) headers.Authorization = "Bearer " + (sessionStorage.getItem("token") || "");
    const response = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : undefined });
    const data = await response.json();
    if (!response.ok) {
        if (authenticated && response.status === 401) {
            sessionStorage.removeItem("token");
            location.assign("/login.html");
        }
        throw new Error(data.message || "Yêu cầu thất bại");
    }
    return data;
}

for (const action of ["login", "signup"]) {
    document.getElementById(action + "-form")?.addEventListener("submit", async event => {
        event.preventDefault();
        const button = event.target.querySelector("button");
        button.disabled = true;
        try {
            const data = await api("/auth/" + action, "POST", Object.fromEntries(new FormData(event.target)));
            if (action === "login") {
                sessionStorage.setItem("token", data.token);
                location.assign("/profile.html");
            } else {
                message.textContent = "Đăng ký thành công. Bạn có thể đăng nhập.";
                event.target.reset();
            }
        } catch (error) { message.textContent = error.message; }
        finally { button.disabled = false; }
    });
}

if (document.getElementById("profile")) {
    api("/users/me", "GET", undefined, true)
        .then(user => { document.getElementById("user-info").textContent = JSON.stringify(user, null, 2); })
        .catch(error => { message.textContent = error.message; });
    document.getElementById("load-users").addEventListener("click", async () => {
        try {
            const users = await api("/users", "GET", undefined, true);
            document.getElementById("users").textContent = JSON.stringify(users, null, 2);
        } catch (error) { message.textContent = error.message; }
    });
    document.getElementById("logout").addEventListener("click", () => {
        sessionStorage.removeItem("token");
        location.assign("/login.html");
    });
}