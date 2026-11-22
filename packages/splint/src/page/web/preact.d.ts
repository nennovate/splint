// What preact.js defines, for the type check: htm's standalone build of Preact, as a classic script.
declare var htmPreact: {
  html: (strings: TemplateStringsArray, ...values: any[]) => any;
  render: (vnode: any, parent: Element | null) => void;
};
