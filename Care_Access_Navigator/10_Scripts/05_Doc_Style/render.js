// Render the house-style HTML documents to PDF with the Care Access Navigator footer.
// Usage: NODE_PATH=<dir with puppeteer> node render.js [render_manifest.json] [filter-substring]
const fs = require("fs");
const path = require("path");
const puppeteer = require("puppeteer");
const manifest = JSON.parse(fs.readFileSync(process.argv[2] || path.join(__dirname, "render_manifest.json"), "utf8"));
const only = process.argv[3];
const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;");

(async () => {
  const browser = await puppeteer.launch({ headless: true, args: ["--no-sandbox", "--allow-file-access-from-files"] });
  const page = await browser.newPage();
  for (const m of manifest) {
    if (only && !m.pdf.includes(only)) continue;
    await page.goto("file://" + m.html, { waitUntil: "networkidle0", timeout: 120000 });
    await page.pdf({
      path: m.pdf, format: "Letter", printBackground: true, preferCSSPageSize: true,
      displayHeaderFooter: true, headerTemplate: "<span></span>",
      footerTemplate: `<div style="width:100%;margin:0 1in;padding-top:4px;border-top:0.5pt solid #CCCCCC;font-family:Helvetica,Arial,sans-serif;font-size:7.5pt;color:#555555;display:flex;justify-content:space-between;">
          <span>${esc(m.footer)}</span><span>Page <span class="pageNumber"></span></span></div>`,
    });
    console.log("wrote", path.basename(m.pdf));
  }
  await browser.close();
})();
