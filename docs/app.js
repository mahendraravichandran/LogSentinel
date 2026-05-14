function attachCopyHandlers() {
  const buttons = document.querySelectorAll("[data-copy]");

  buttons.forEach((button) => {
    button.addEventListener("click", async () => {
      const text = button.getAttribute("data-copy") || "";
      const originalText = button.textContent;

      try {
        await navigator.clipboard.writeText(text);
        button.textContent = "Copied";
      } catch {
        button.textContent = "Copy failed";
      }

      setTimeout(() => {
        button.textContent = originalText;
      }, 1100);
    });
  });
}

function attachRevealAnimation() {
  const items = document.querySelectorAll(".reveal");
  if (!items.length) {
    return;
  }

  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add("visible");
          observer.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.12 }
  );

  items.forEach((item) => observer.observe(item));
}

function attachScrollProgress() {
  const bar = document.getElementById("scroll-progress");
  if (!bar) {
    return;
  }

  const update = () => {
    const scrollTop = window.scrollY;
    const docHeight = document.documentElement.scrollHeight - window.innerHeight;
    const ratio = docHeight > 0 ? (scrollTop / docHeight) * 100 : 0;
    bar.style.width = `${Math.min(100, Math.max(0, ratio))}%`;
  };

  window.addEventListener("scroll", update, { passive: true });
  update();
}

function attachActiveSectionTracking() {
  const navLinks = Array.from(document.querySelectorAll(".quick-nav a"));
  if (!navLinks.length) {
    return;
  }

  const sections = navLinks
    .map((link) => {
      const id = link.getAttribute("href");
      if (!id || !id.startsWith("#")) {
        return null;
      }
      const section = document.querySelector(id);
      return section ? { link, section } : null;
    })
    .filter(Boolean);

  const setActive = (id) => {
    navLinks.forEach((link) => {
      link.classList.toggle("active", link.getAttribute("href") === id);
    });
  };

  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          setActive(`#${entry.target.id}`);
        }
      });
    },
    { rootMargin: "-25% 0px -60% 0px", threshold: 0.1 }
  );

  sections.forEach(({ section }) => observer.observe(section));
}

document.addEventListener("DOMContentLoaded", () => {
  attachCopyHandlers();
  attachRevealAnimation();
  attachScrollProgress();
  attachActiveSectionTracking();
});
