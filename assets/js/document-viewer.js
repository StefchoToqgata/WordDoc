(() => {
  const $ = (id) => document.getElementById(id);
  const input = $('documentFile');
  const drop = $('dropZone');
  const empty = $('emptyViewer');
  const pdf = $('pdfFrame');
  const canvas = $('documentCanvas');
  const page = $('documentPage');
  const warning = $('warningBar');
  const meta = $('fileMeta');
  const status = $('statusMessage');
  const search = $('documentSearch');
  const searchCount = $('searchCount');
  const buttons = {
    clear: $('clearFile'), open: $('openDocument'), print: $('printDocument'),
    zoomIn: $('zoomIn'), zoomOut: $('zoomOut')
  };

  const MAX_SIZE = 50 * 1024 * 1024;
  let file = null;
  let objectUrl = '';
  let originalHtml = '';
  let mode = '';
  let zoom = 1;

  const ext = (name) => name.includes('.') ? name.split('.').pop().toLowerCase() : '';
  const byName = (node, name) => Array.from(node?.getElementsByTagName('*') || []).filter((item) => item.localName === name);
  const first = (node, name) => byName(node, name)[0] || null;
  const attr = (node, name) => Array.from(node?.attributes || []).find((item) => item.localName === name)?.value || '';
  const u16 = (view, offset) => view.getUint16(offset, true);
  const u32 = (view, offset) => view.getUint32(offset, true);

  function setStatus(message, type = '') {
    status.textContent = message;
    status.className = `status-message ${type}`.trim();
  }

  function setControls(enabled) {
    buttons.clear.disabled = !enabled;
    buttons.open.disabled = !enabled;
    buttons.print.disabled = !enabled;
    const textMode = enabled && mode === 'html';
    buttons.zoomIn.disabled = !textMode;
    buttons.zoomOut.disabled = !textMode;
    search.disabled = !textMode;
  }

  function clearUrls() {
    if (objectUrl) URL.revokeObjectURL(objectUrl);
    objectUrl = '';
  }

  function reset() {
    clearUrls();
    file = null;
    mode = '';
    zoom = 1;
    originalHtml = '';
    input.value = '';
    meta.classList.remove('visible');
    empty.classList.remove('hidden');
    pdf.style.display = 'none';
    pdf.removeAttribute('src');
    canvas.style.display = 'none';
    page.innerHTML = '';
    page.style.zoom = 1;
    warning.classList.add('hidden');
    warning.textContent = '';
    search.value = '';
    searchCount.textContent = '';
    setControls(false);
    setStatus('Choose a PDF, DOCX, or DOC file.');
  }

  function showMeta(selected) {
    const units = ['B', 'KB', 'MB', 'GB'];
    const index = selected.size ? Math.min(Math.floor(Math.log(selected.size) / Math.log(1024)), 3) : 0;
    $('fileName').textContent = selected.name;
    $('fileType').textContent = ext(selected.name).toUpperCase();
    $('fileSize').textContent = `${(selected.size / (1024 ** index)).toFixed(index ? 1 : 0)} ${units[index]}`;
    $('fileDate').textContent = selected.lastModified ? new Date(selected.lastModified).toLocaleString() : 'Not available';
    meta.classList.add('visible');
  }

  function showHtml(container, note) {
    originalHtml = container.innerHTML || '<p>This document did not contain readable text.</p>';
    page.innerHTML = originalHtml;
    mode = 'html';
    canvas.style.display = 'block';
    pdf.style.display = 'none';
    empty.classList.add('hidden');
    warning.textContent = note;
    warning.classList.toggle('hidden', !note);
    setControls(true);
  }

  async function inflate(bytes) {
    if (!window.DecompressionStream) throw new Error('Your browser cannot unpack DOCX files locally. Update Chrome, Edge, Firefox, or Safari.');
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
    return new Uint8Array(await new Response(stream).arrayBuffer());
  }

  async function unzip(buffer) {
    const bytes = new Uint8Array(buffer);
    const view = new DataView(buffer);
    let end = -1;
    for (let i = bytes.length - 22; i >= Math.max(0, bytes.length - 65557); i -= 1) {
      if (u32(view, i) === 0x06054b50) { end = i; break; }
    }
    if (end < 0) throw new Error('This DOCX file is damaged or is not a valid DOCX file.');

    const files = {};
    const decoder = new TextDecoder();
    const count = u16(view, end + 10);
    let cursor = u32(view, end + 16);
    for (let i = 0; i < count; i += 1) {
      if (u32(view, cursor) !== 0x02014b50) throw new Error('The DOCX directory is damaged.');
      const method = u16(view, cursor + 10);
      const size = u32(view, cursor + 20);
      const nameLength = u16(view, cursor + 28);
      const extraLength = u16(view, cursor + 30);
      const commentLength = u16(view, cursor + 32);
      const local = u32(view, cursor + 42);
      const name = decoder.decode(bytes.subarray(cursor + 46, cursor + 46 + nameLength));
      const dataStart = local + 30 + u16(view, local + 26) + u16(view, local + 28);
      const compressed = bytes.subarray(dataStart, dataStart + size);
      if (!name.endsWith('/')) {
        if (method === 0) files[name] = new Uint8Array(compressed);
        else if (method === 8) files[name] = await inflate(compressed);
        else throw new Error(`Unsupported DOCX compression method ${method}.`);
      }
      cursor += 46 + nameLength + extraLength + commentLength;
    }
    return files;
  }

  function parseXml(bytes, label) {
    const xml = new TextDecoder().decode(bytes || new Uint8Array());
    const documentNode = new DOMParser().parseFromString(xml, 'application/xml');
    if (!xml || documentNode.querySelector('parsererror')) throw new Error(`${label} could not be read.`);
    return documentNode;
  }

  function renderRun(run, target) {
    let output = target;
    const properties = first(run, 'rPr');
    if (properties) {
      const span = document.createElement('span');
      if (first(properties, 'b')) span.style.fontWeight = '700';
      if (first(properties, 'i')) span.style.fontStyle = 'italic';
      if (first(properties, 'u')) span.style.textDecoration = 'underline';
      output.appendChild(span);
      output = span;
    }
    Array.from(run.children).forEach((child) => {
      if (child.localName === 't' || child.localName === 'instrText') output.append(document.createTextNode(child.textContent || ''));
      if (child.localName === 'tab') output.append(document.createTextNode('\t'));
      if (child.localName === 'br' || child.localName === 'cr') output.appendChild(document.createElement('br'));
    });
  }

  function renderParagraph(paragraph, relationships) {
    const properties = first(paragraph, 'pPr');
    const style = attr(first(properties, 'pStyle'), 'val').toLowerCase();
    const tag = style.includes('title') ? 'h1' : style.includes('heading1') ? 'h2' : style.includes('heading2') ? 'h3' : 'p';
    const output = document.createElement(tag);
    if (first(properties, 'numPr')) output.append(document.createTextNode('• '));

    Array.from(paragraph.children).forEach((child) => {
      if (child.localName === 'r') renderRun(child, output);
      if (child.localName === 'hyperlink') {
        const relationship = relationships.get(attr(child, 'id'));
        const link = document.createElement(relationship ? 'a' : 'span');
        if (relationship && /^(https?:|mailto:)/i.test(relationship)) {
          link.href = relationship;
          link.target = '_blank';
          link.rel = 'noreferrer';
        }
        byName(child, 'r').forEach((run) => renderRun(run, link));
        output.appendChild(link);
      }
    });
    if (!output.textContent.trim()) output.appendChild(document.createElement('br'));
    return output;
  }

  function renderTable(table, relationships) {
    const output = document.createElement('table');
    byName(table, 'tr').filter((row) => row.parentElement === table).forEach((row) => {
      const tr = document.createElement('tr');
      byName(row, 'tc').filter((cell) => cell.parentElement === row).forEach((cell) => {
        const td = document.createElement('td');
        byName(cell, 'p').filter((p) => p.parentElement === cell).forEach((p) => td.appendChild(renderParagraph(p, relationships)));
        tr.appendChild(td);
      });
      output.appendChild(tr);
    });
    return output;
  }

  async function renderDocx(selected) {
    const files = await unzip(await selected.arrayBuffer());
    const doc = parseXml(files['word/document.xml'], 'The DOCX document');
    const relationships = new Map();
    if (files['word/_rels/document.xml.rels']) {
      const rels = parseXml(files['word/_rels/document.xml.rels'], 'Document links');
      byName(rels, 'Relationship').forEach((item) => {
        if (item.getAttribute('TargetMode') === 'External') relationships.set(item.getAttribute('Id'), item.getAttribute('Target'));
      });
    }
    const body = byName(doc, 'body')[0];
    if (!body) throw new Error('The DOCX document has no readable body.');
    const output = document.createElement('div');
    Array.from(body.children).forEach((child) => {
      if (child.localName === 'p') output.appendChild(renderParagraph(child, relationships));
      if (child.localName === 'tbl') output.appendChild(renderTable(child, relationships));
    });
    showHtml(output, 'Opened locally. Exact Word page breaks, fonts, and spacing may look slightly different.');
  }

  async function renderDoc(selected) {
    const buffer = await selected.arrayBuffer();
    const bytes = new Uint8Array(buffer);
    const texts = [new TextDecoder('utf-16le').decode(bytes), new TextDecoder('windows-1252').decode(bytes)];
    const lines = [...new Set(texts.flatMap((text) => text.match(/[A-Za-z0-9À-ž£€$%&@(),.;:'"!?+\-\/=\\\s]{8,}/g) || [])
      .map((line) => line.replace(/[\u0000-\u001F\u007F]/g, ' ').replace(/\s+/g, ' ').trim())
      .filter((line) => line.length > 7 && /[A-Za-zÀ-ž]{3}/.test(line)))].slice(0, 600);
    const output = document.createElement('div');
    const heading = document.createElement('h1');
    heading.textContent = selected.name.replace(/\.doc$/i, '');
    output.appendChild(heading);
    lines.forEach((line) => { const p = document.createElement('p'); p.textContent = line; output.appendChild(p); });
    if (!lines.length) output.append('No reliable readable text could be extracted.');
    showHtml(output, 'Legacy DOC preview is best-effort text only. Formatting, images, and tables may not appear.');
  }

  function renderPdf(selected) {
    objectUrl = URL.createObjectURL(selected);
    mode = 'pdf';
    pdf.src = `${objectUrl}#toolbar=1&navpanes=1&view=FitH`;
    pdf.style.display = 'block';
    canvas.style.display = 'none';
    empty.classList.add('hidden');
    warning.classList.add('hidden');
    searchCount.textContent = 'Use Ctrl+F';
    setControls(true);
  }

  async function handle(selected) {
    if (!selected) return;
    const extension = ext(selected.name);
    if (!['pdf', 'docx', 'doc'].includes(extension)) return setStatus('Unsupported file. Use PDF, DOCX, or DOC.', 'error');
    if (selected.size > MAX_SIZE) return setStatus('This file is over the 50 MB limit.', 'error');
    clearUrls();
    file = selected;
    showMeta(selected);
    setStatus('Opening file locally…');
    try {
      if (extension === 'pdf') renderPdf(selected);
      if (extension === 'docx') await renderDocx(selected);
      if (extension === 'doc') await renderDoc(selected);
      setStatus('Ready. The file has not been uploaded anywhere.', 'success');
    } catch (error) {
      console.error(error);
      reset();
      setStatus(error.message || 'The document could not be opened.', 'error');
    }
  }

  function highlight(term) {
    page.innerHTML = originalHtml;
    term = term.trim();
    if (!term) return void (searchCount.textContent = '');
    const nodes = [];
    const walker = document.createTreeWalker(page, NodeFilter.SHOW_TEXT);
    while (walker.nextNode()) if (walker.currentNode.nodeValue.trim()) nodes.push(walker.currentNode);
    const pattern = new RegExp(term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
    let count = 0;
    nodes.forEach((node) => {
      const parts = node.nodeValue.split(pattern);
      const matches = node.nodeValue.match(pattern) || [];
      if (!matches.length) return;
      const fragment = document.createDocumentFragment();
      parts.forEach((part, index) => {
        fragment.append(part);
        if (matches[index]) { const mark = document.createElement('mark'); mark.textContent = matches[index]; fragment.appendChild(mark); count += 1; }
      });
      node.replaceWith(fragment);
    });
    searchCount.textContent = `${count} match${count === 1 ? '' : 'es'}`;
    page.querySelector('mark')?.scrollIntoView({ block: 'center', behavior: 'smooth' });
  }

  input.addEventListener('change', () => handle(input.files[0]));
  drop.addEventListener('click', () => input.click());
  drop.addEventListener('keydown', (event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); input.click(); } });
  ['dragenter', 'dragover'].forEach((name) => drop.addEventListener(name, (event) => { event.preventDefault(); drop.classList.add('dragover'); }));
  ['dragleave', 'drop'].forEach((name) => drop.addEventListener(name, (event) => { event.preventDefault(); drop.classList.remove('dragover'); }));
  drop.addEventListener('drop', (event) => handle(event.dataTransfer.files[0]));
  buttons.clear.addEventListener('click', reset);
  buttons.open.addEventListener('click', () => { if (file) window.open(objectUrl || URL.createObjectURL(file), '_blank', 'noopener,noreferrer'); });
  buttons.print.addEventListener('click', () => mode === 'pdf' ? window.open(objectUrl, '_blank', 'noopener,noreferrer') : window.print());
  buttons.zoomIn.addEventListener('click', () => { zoom = Math.min(1.5, zoom + .1); page.style.zoom = zoom; });
  buttons.zoomOut.addEventListener('click', () => { zoom = Math.max(.7, zoom - .1); page.style.zoom = zoom; });
  search.addEventListener('input', () => highlight(search.value));
  window.addEventListener('beforeunload', clearUrls);
  reset();
})();
