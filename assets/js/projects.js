(() => {
  const buttons = document.querySelectorAll('[data-filter]');
  const cards = document.querySelectorAll('[data-category]');

  buttons.forEach((button) => {
    button.addEventListener('click', () => {
      const filter = button.dataset.filter;
      buttons.forEach((item) => item.classList.toggle('active', item === button));
      cards.forEach((card) => {
        const visible = filter === 'all' || card.dataset.category === filter;
        card.classList.toggle('hidden', !visible);
      });
    });
  });
})();
