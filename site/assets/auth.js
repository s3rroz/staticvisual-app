(function () {
  // ← домен Deno Deploy (тот же, что в Config.cs приложения). Пример: https://staticvisual-xxx.deno.dev
  // Тот же origin, что и API (сервер отдаёт и сайт, и /api/*) — оставляем пустым.
  window.API_BASE = "";
  window.apiURL = function (path) { return (window.API_BASE || "") + path; };

  window.svGetToken = function () {
    return localStorage.getItem("sv_token") || sessionStorage.getItem("sv_token") || "";
  };
  window.svSetToken = function (token, remember) {
    if (remember) {
      localStorage.setItem("sv_token", token);
      sessionStorage.removeItem("sv_token");
    } else {
      sessionStorage.setItem("sv_token", token);
      localStorage.removeItem("sv_token");
    }
  };
  window.svClearToken = function () {
    localStorage.removeItem("sv_token");
    sessionStorage.removeItem("sv_token");
  };
})();
