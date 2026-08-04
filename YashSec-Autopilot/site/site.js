(() => {
  const config = window.YASHSEC_SITE_CONFIG || {};
  const githubUrl = config.githubUrl || '';
  const liveDemoUrl = config.liveDemoUrl || '';
  ['githubNav', 'githubButton', 'githubButtonBottom'].forEach((id) => {
    const node = document.getElementById(id);
    if (!node) return;
    if (githubUrl) { node.href = githubUrl; node.target = '_blank'; node.rel = 'noopener noreferrer'; }
    else { node.classList.add('disabled'); }
  });
  ['demoButton', 'demoButtonBottom'].forEach((id) => {
    const node = document.getElementById(id);
    if (!node) return;
    if (liveDemoUrl) {
      node.href = liveDemoUrl;
      node.textContent = 'Open read-only live demo';
      node.classList.remove('disabled');
      node.target = '_blank';
      node.rel = 'noopener noreferrer';
    }
  });
})();
