const navToggle = document.querySelector(".nav-toggle");
const siteNav = document.querySelector(".site-nav");
const header = document.querySelector("[data-header]");
const year = document.querySelector("[data-year]");

if (year) {
  year.textContent = new Date().getFullYear();
}

if (navToggle && siteNav) {
  navToggle.addEventListener("click", () => {
    const isOpen = navToggle.getAttribute("aria-expanded") === "true";

    navToggle.setAttribute("aria-expanded", String(!isOpen));
    navToggle.classList.toggle("is-open", !isOpen);
    siteNav.classList.toggle("is-open", !isOpen);
    document.body.classList.toggle("nav-open", !isOpen);
  });

  siteNav.addEventListener("click", (event) => {
    if (!(event.target instanceof HTMLAnchorElement)) {
      return;
    }

    navToggle.setAttribute("aria-expanded", "false");
    navToggle.classList.remove("is-open");
    siteNav.classList.remove("is-open");
    document.body.classList.remove("nav-open");
  });
}

const setHeaderShadow = () => {
  if (!header) {
    return;
  }

  header.classList.toggle("has-shadow", window.scrollY > 8);
};

setHeaderShadow();
window.addEventListener("scroll", setHeaderShadow, { passive: true });
