try { const theme = localStorage.getItem('nimstead-docs-theme'); if (theme === 'light' || theme === 'dark') document.documentElement.dataset.theme = theme; } catch {}
