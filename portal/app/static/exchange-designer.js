/* Form-only editor; JSON is an internal transport, never an executable template. */
(() => {
  "use strict";
  const metadata = document.querySelector("#metadata-editor");
  if (metadata) metadata.addEventListener("submit", () => {
    metadata.elements.values.value = JSON.stringify(Object.fromEntries(
      [...metadata.querySelectorAll("[data-metadata-key]")].map(input => [input.dataset.metadataKey, input.value])));
  });
  const form = document.querySelector("#template-designer");
  if (!form) return;
  const catalog = JSON.parse(document.querySelector("#template-catalog").textContent);
  const fields = JSON.parse(document.querySelector("#field-catalog").textContent);
  const source = document.querySelector("#designer-source");
  const editable = form.dataset.editable === "true";
  const el = name => document.querySelector(`#designer-${name}`);
  let current, baseline, customId = "";
  const clone = value => JSON.parse(JSON.stringify(value));
  function control(label, type, value, change, options) {
    const wrapper = document.createElement("label");
    wrapper.append(document.createTextNode(label + " "));
    const input = document.createElement(type === "select" ? "select" : "input");
    if (type !== "select") input.type = type;
    if (options) Object.entries(options).forEach(([key, name]) => input.add(new Option(name, key)));
    if (type === "checkbox") input.checked = !!value;
    else input.value = value ?? "";
    if (type === "text") input.maxLength = label === "Default" ? 2000 : 120;
    if (type === "number") { input.min = "8"; input.max = "80"; }
    if (label === "Label") input.required = true;
    input.addEventListener("change", () => change(type === "checkbox" ? input.checked : type === "number" ? Number(input.value) : input.value));
    wrapper.append(input);
    return wrapper;
  }
  function mappings(section) {
    const container = el(section);
    container.replaceChildren();
    const available = section === "metadata" ? fields.metadata : {...fields.metadata, ...fields.datasets[current.dataset]};
    current[section].forEach((mapping, index) => {
      const row = document.createElement("fieldset");
      const legend = document.createElement("legend"); legend.textContent = `${index + 1}. ${mapping.label}`; row.append(legend);
      row.append(control("Catalog field", "select", mapping.field, value => { mapping.field = value; }, available));
      row.append(control("Label", "text", mapping.label, value => { mapping.label = value; legend.textContent = `${index + 1}. ${value}`; }));
      row.append(control("Direction", "select", mapping.direction || "both", value => { mapping.direction = value; }, {both: "Import and export", export: "Export only", import: "Import only", display: "Display in export"}));
      row.append(control("Default", "text", mapping.default, value => { mapping.default = value; }));
      row.append(control("Required", "checkbox", mapping.required, value => { mapping.required = value; }));
      if (section === "columns") row.append(control("Width", "number", mapping.width || 24, value => { mapping.width = value; }));
      for (const [label, offset] of [["Move up", -1], ["Move down", 1], ["Remove", 0]]) {
        const button = document.createElement("button"); button.type = "button"; button.textContent = label;
        button.disabled = offset < 0 && index === 0 || offset > 0 && index === current[section].length - 1;
        button.addEventListener("click", () => {
          if (!offset) current[section].splice(index, 1);
          else [current[section][index], current[section][index + offset]] = [current[section][index + offset], current[section][index]];
          mappings(section);
        }); row.append(button);
      }
      container.append(row);
    });
  }
  function render() {
    el("name").value = current.name;
    el("description").value = current.description || "";
    el("dataset").value = current.dataset;
    el("sheet").value = current.layout.sheet || "";
    el("banner").value = current.layout.banner || "";
    el("color").value = "#" + (current.layout.header_color || "17312B");
    el("height").value = current.layout.row_height || 32;
    el("policy").value = current.block_missing ? "block" : "acknowledge";
    form.elements.enabled.checked = current.enabled !== false;
    form.elements.template_id.value = customId;
    el("fields").disabled = !editable || (!customId && !current.isNew);
    el("status").textContent = current.isNew ? "New copy — choose a name and save." : customId ? "Editing a custom template." : "Built-in template — duplicate it to make changes.";
    mappings("metadata"); mappings("columns");
  }
  function load() { customId = /^\d+$/.test(source.value) ? source.value : ""; current = clone(catalog[source.value]); baseline = clone(current); render(); }
  source.addEventListener("change", load);
  document.querySelector("#designer-duplicate")?.addEventListener("click", () => {
    current = clone(catalog[source.value]); current.name += " (copy)"; current.isNew = true; current.enabled = true; customId = ""; baseline = clone(current); render();
  });
  el("reset")?.addEventListener("click", () => { current = clone(baseline); render(); });
  el("dataset").addEventListener("change", () => {
    current.dataset = el("dataset").value;
    current.columns = clone(catalog[current.dataset].columns);
    mappings("columns");
    el("status").textContent = "Dataset changed; columns now use that dataset's built-in mappings.";
  });
  form.querySelectorAll("[data-add]").forEach(button => button.addEventListener("click", () => {
    const section = button.dataset.add;
    const available = section === "metadata" ? fields.metadata : fields.datasets[current.dataset];
    const field = Object.keys(available)[0];
    current[section].push({field, label: available[field], direction: "export", width: 24});
    mappings(section);
  }));
  form.addEventListener("submit", event => {
    if (!editable || el("fields").disabled) { event.preventDefault(); return; }
    current.name = el("name").value; current.description = el("description").value;
    current.block_missing = el("policy").value === "block";
    current.layout = {...current.layout, sheet: el("sheet").value, banner: el("banner").value, header_color: el("color").value.slice(1), row_height: Number(el("height").value)};
    delete current.isNew;
    form.elements.definition.value = JSON.stringify(current);
  });
  load();
})();
