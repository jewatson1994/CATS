(function () {
  "use strict";
  const header = document.querySelector("header");
  if (!header) return;
  const menus = Array.from(header.querySelectorAll("details.notification-menu, details.admin-menu, details.user-menu"));
  const closeMenus = (except) => menus.forEach((menu) => { if (menu !== except) menu.removeAttribute("open"); });
  menus.forEach((menu) => {
    menu.addEventListener("toggle", () => { if (menu.open) closeMenus(menu); });
    const summary = menu.querySelector(":scope > summary");
    if (summary) summary.addEventListener("click", () => { if (!menu.open) closeMenus(menu); });
    menu.querySelectorAll("a").forEach((link) => link.addEventListener("click", () => closeMenus()));
  });
  header.querySelectorAll("a").forEach((link) => link.addEventListener("click", () => closeMenus()));
  document.addEventListener("click", (event) => { if (!header.contains(event.target)) closeMenus(); });
  document.addEventListener("keydown", (event) => { if (event.key === "Escape") closeMenus(); });
  window.addEventListener("beforeunload", () => closeMenus());
})();
