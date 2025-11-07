document.addEventListener('DOMContentLoaded', () => {
    const tabs = document.querySelectorAll('.settings-tab');
    const sections = document.querySelectorAll('.settings-section');

    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const tabId = tab.dataset.tab;

            tabs.forEach(t => t.classList.remove('is-active'));
            tab.classList.add('is-active');

            sections.forEach(section => {
                if (section.id === tabId) {
                    section.classList.add('is-active');
                } else {
                    section.classList.remove('is-active');
                }
            });
        });
    });

    const searchInputs = document.querySelectorAll('input[name="search_users"], input[name="search_universes"]');
    searchInputs.forEach(input => {
        input.addEventListener('input', () => {
            if (input.value === '') {
                const currentTab = document.querySelector('.settings-tab.is-active').dataset.tab;
                window.location.href = `/admin?tab=${currentTab}`;
            }
        });
    });
});