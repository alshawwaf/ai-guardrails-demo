// Theme toggle (light / dark). A static file rather than an inline script so
// every page works under the Content-Security-Policy (script-src 'self').
(function () {
  const themeToggle = document.getElementById("theme-toggle");
  const sunIcon = document.querySelector(".sun-icon");
  const moonIcon = document.querySelector(".moon-icon");
  if (!themeToggle || !sunIcon || !moonIcon) return;

  let savedTheme = null;
  try {
    savedTheme = localStorage.getItem("theme");
  } catch (e) {
    savedTheme = null; // storage blocked: follow the system preference
  }
  const systemPrefersLight = window.matchMedia("(prefers-color-scheme: light)").matches;

  if (savedTheme === "light" || (!savedTheme && systemPrefersLight)) {
    document.documentElement.setAttribute("data-theme", "light");
    sunIcon.style.display = "none";
    moonIcon.style.display = "block";
  }

  const remember = (value) => {
    try {
      localStorage.setItem("theme", value);
    } catch (e) {
      /* not persisted */
    }
  };

  themeToggle.addEventListener("click", () => {
    const currentTheme = document.documentElement.getAttribute("data-theme");
    if (currentTheme === "light") {
      document.documentElement.removeAttribute("data-theme");
      remember("dark");
      sunIcon.style.display = "block";
      moonIcon.style.display = "none";
    } else {
      document.documentElement.setAttribute("data-theme", "light");
      remember("light");
      sunIcon.style.display = "none";
      moonIcon.style.display = "block";
    }
  });
})();
