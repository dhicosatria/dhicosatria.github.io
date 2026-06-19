(function () {
  function setupBlock(block) {
    var rows = Array.prototype.slice.call(block.querySelectorAll('.catalog-row'));
    var pager = block.querySelector('.catalog-pagination');
    var summary = block.querySelector('.catalog-summary');
    if (!rows.length || !pager) return;

    var perPage = Number(block.getAttribute('data-per-page') || 5);
    var totalPages = Math.ceil(rows.length / perPage);
    var current = 0;

    var prev = pager.querySelector('[data-page="prev"]');
    var next = pager.querySelector('[data-page="next"]');
    var pageButtons = Array.prototype.slice.call(pager.querySelectorAll('[data-page-number]'));

    function render() {
      rows.forEach(function (row, index) {
        row.hidden = Math.floor(index / perPage) !== current;
      });

      var start = current * perPage + 1;
      var end = Math.min((current + 1) * perPage, rows.length);
      if (summary) summary.textContent = '— showing ' + start + '-' + end + ' of ' + rows.length;

      if (prev) prev.disabled = current === 0;
      if (next) next.disabled = current === totalPages - 1;

      pageButtons.forEach(function (button, index) {
        button.classList.toggle('is-active', index === current);
        button.setAttribute('aria-current', index === current ? 'page' : 'false');
      });
    }

    pageButtons.forEach(function (button, index) {
      button.addEventListener('click', function () {
        current = index;
        render();
      });
    });

    if (prev) {
      prev.addEventListener('click', function () {
        if (current > 0) {
          current -= 1;
          render();
        }
      });
    }

    if (next) {
      next.addEventListener('click', function () {
        if (current < totalPages - 1) {
          current += 1;
          render();
        }
      });
    }

    render();
  }

  function init() {
    document.querySelectorAll('.catalog-block').forEach(setupBlock);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
