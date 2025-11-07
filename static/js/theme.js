document.addEventListener('DOMContentLoaded', function() {
    const themeToggleButton = document.getElementById('theme-toggle');

    if (themeToggleButton) {
        themeToggleButton.addEventListener('click', () => {
            let theme = document.documentElement.classList.contains('light-theme') ? 'dark' : 'light';
            document.documentElement.classList.remove('light-theme', 'dark-theme');
            document.documentElement.classList.add(`${theme}-theme`);
            localStorage.setItem('theme', theme);
        });
    }
});