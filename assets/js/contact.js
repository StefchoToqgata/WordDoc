(() => {
  const form = document.querySelector('[data-contact-form]');
  if (!form) return;

  form.addEventListener('submit', (event) => {
    event.preventDefault();
    const data = new FormData(form);
    const name = String(data.get('name') || '').trim();
    const email = String(data.get('email') || '').trim();
    const message = String(data.get('message') || '').trim();

    if (!name || !email || !message) {
      window.showToast('Complete all fields first.');
      return;
    }

    const subject = encodeURIComponent(`Portfolio message from ${name}`);
    const body = encodeURIComponent(`${message}\n\nReply to: ${email}`);
    window.location.href = `mailto:janian1nikolov@gmail.com?subject=${subject}&body=${body}`;
  });
})();
