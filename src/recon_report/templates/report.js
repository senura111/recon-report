"use strict";
// The report's only script, allowed by its CSP hash. The button starts hidden so
// it never shows without JavaScript; the <noscript> hint covers that case.
const savePdf = document.getElementById("save-pdf");
savePdf.addEventListener("click", () => window.print());
savePdf.hidden = false;
