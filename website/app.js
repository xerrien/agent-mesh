document.querySelectorAll("[data-copy]").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const selector = btn.getAttribute("data-copy");
    const el = document.querySelector(selector);
    if (!el) return;
    await navigator.clipboard.writeText(el.innerText);
    const original = btn.innerText;
    btn.innerText = "Copied";
    setTimeout(() => { btn.innerText = original; }, 1200);
  });
});

if (location.pathname.includes("/docs/")) {
  const page = location.pathname.split("/").pop() || "index.html";
  document.querySelectorAll(".docs-sidebar a").forEach((a) => {
    const href = a.getAttribute("href") || "";
    if (href.endsWith(page)) a.classList.add("active");
  });
}

