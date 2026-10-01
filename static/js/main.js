// ============================================
// Main Entry Point
// ============================================

import { getAttackColor } from './shared/utils.js';
import { displayResults } from './shared/traffic-flow.js';

// Expose utilities globally for backward compatibility
window.getAttackColor = getAttackColor;
window.displayResults = displayResults;

document.addEventListener("DOMContentLoaded", () => {
  // Mobile Menu Toggle
  const mobileMenuToggle = document.getElementById("mobile-menu-toggle");
  const mainNav = document.getElementById("main-nav");

  if (mobileMenuToggle && mainNav) {
    mobileMenuToggle.addEventListener("click", () => {
      mobileMenuToggle.classList.toggle("active");
      mainNav.classList.toggle("active");
    });

    // Close menu when clicking a nav link
    const navLinks = mainNav.querySelectorAll("a");
    navLinks.forEach((link) => {
      link.addEventListener("click", () => {
        mobileMenuToggle.classList.remove("active");
        mainNav.classList.remove("active");
      });
    });
  }

  // Page routing - load appropriate module based on page
  if (document.querySelector(".gateway-page")) {
    console.log("Initializing Gateway Mode...");
    import('./pages/gateway.js').then(module => {
      module.initGateway();
    });
  } else if (document.getElementById("prompt")) {
    console.log("Initializing Playground...");
    import('./pages/playground.js').then(module => {
      module.initPlayground();
    });
  } else if (document.getElementById("total-scans")) {
    console.log("Initializing Dashboard...");
    import('./pages/dashboard.js').then(module => {
      module.initDashboard();
    });
  } else if (document.getElementById("logs-table")) {
    console.log("Initializing Logs...");
    import('./pages/logs.js').then(module => {
      module.initLogs();
    });
  } else if (document.querySelector(".benchmark-page")) {
    console.log("Initializing Benchmarking...");
    import('./pages/benchmarking.js?v=3').then(module => {
      module.initBenchmarking();
    });
  } else if (document.querySelector(".settings-form")) {
    console.log("Initializing Settings...");
    import('./pages/settings.js').then(module => {
      module.initSettings();
    });
  } else {
    console.log("No specific page detected.");
  }
});
