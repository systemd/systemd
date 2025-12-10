
/* Progressive enhancement to improve the readability of index entries. This takes Sphinx index entries like `binfmt.d — Configure additional binary formats for executables at boot` and splits them into two separate <spans> at the first whitespace. This creates a more stylable index entry:

<a class="reference internal" href="docs/binfmt.d.html">
  <span class="reference-name">binfmt.d</span> <span class="reference-description">— Configure additional binary formats for executables at boot</span>
</a>
*/

document.querySelectorAll(".sidebar-tree .reference.internal, .toctree-wrapper .reference.internal").forEach(function(link) {
    const text = link.textContent.trim();

    // Split at the first space
    const firstSpaceIndex = text.indexOf(" ");
    if (firstSpaceIndex === -1) return; // nothing to split

    const firstPart = text.slice(0, firstSpaceIndex);
    const secondPart = text.slice(firstSpaceIndex + 1);

    // Wrap in spans
    link.innerHTML = `<span class="reference-name">${firstPart}</span> <span class="reference-description">${secondPart}</span>`;
});
