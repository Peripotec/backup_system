/**
 * FilterBar - Componente unificado de filtrado para Backup Manager
 * Soporta filtrado server-side con persistencia en URL params
 */
class FilterBar {
    constructor(options) {
        this.container = document.querySelector(options.container);
        this.filters = options.filters || [];
        this.searchEnabled = options.searchEnabled !== false;
        this.searchPlaceholder = options.searchPlaceholder || '🔍 Buscar...';
        this.onFilter = options.onFilter || (() => { });
        this.storageKey = options.storageKey || 'filterbar_' + window.location.pathname;
        this.showCount = options.showCount !== false;
        this.countElement = null;

        this.init();
    }

    init() {
        this.render();
        this.loadFromURL();
        this.bindEvents();
    }

    render() {
        const html = `
            <div class="filter-bar">
                <div class="filter-bar-content">
                    ${this.filters.map(f => this.renderFilter(f)).join('')}
                    ${this.searchEnabled ? `
                        <div class="filter-item filter-search">
                            <input type="text" class="form-control form-control-sm" 
                                   id="filter-search" placeholder="${this.searchPlaceholder}">
                        </div>
                    ` : ''}
                    <div class="filter-actions">
                        <button type="button" class="btn btn-sm btn-outline-secondary" id="filter-clear" title="Limpiar filtros">
                            🗑️
                        </button>
                    </div>
                </div>
                ${this.showCount ? '<div class="filter-count"><small class="text-muted" id="filter-result-count"></small></div>' : ''}
            </div>
        `;
        this.container.innerHTML = html;
        this.countElement = document.getElementById('filter-result-count');
    }

    renderFilter(filter) {
        if (filter.type === 'select') {
            const optionsHtml = filter.options === 'dynamic'
                ? `<option value="">${filter.label}</option>`
                : `<option value="">${filter.label}</option>` +
                filter.options.map(o =>
                    typeof o === 'string'
                        ? `<option value="${o}">${o}</option>`
                        : `<option value="${o.value}">${o.label}</option>`
                ).join('');

            return `
                <div class="filter-item">
                    <select class="form-select form-select-sm filter-select" 
                            id="filter-${filter.id}" data-filter="${filter.id}">
                        ${optionsHtml}
                    </select>
                </div>
            `;
        }
        return '';
    }

    bindEvents() {
        // Select changes
        this.container.querySelectorAll('.filter-select').forEach(sel => {
            sel.addEventListener('change', () => this.applyFilters());
        });

        // Search with debounce
        const searchInput = document.getElementById('filter-search');
        if (searchInput) {
            let debounceTimer;
            searchInput.addEventListener('input', () => {
                clearTimeout(debounceTimer);
                debounceTimer = setTimeout(() => this.applyFilters(), 300);
            });

            // Enter key immediate search
            searchInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    clearTimeout(debounceTimer);
                    this.applyFilters();
                }
            });
        }

        // Clear button
        document.getElementById('filter-clear')?.addEventListener('click', () => this.clearFilters());
    }

    /**
     * Populate a dynamic filter with options
     * @param {string} filterId - Filter ID
     * @param {Array} options - Array of {value, label} or strings
     * @param {boolean} keepSelection - Keep current selection if valid
     */
    populateFilter(filterId, options, keepSelection = true) {
        const select = document.getElementById(`filter-${filterId}`);
        if (!select) return;

        const currentValue = select.value;
        const filter = this.filters.find(f => f.id === filterId);
        const label = filter ? filter.label : filterId;

        let html = `<option value="">${label}</option>`;
        options.forEach(opt => {
            if (typeof opt === 'string') {
                html += `<option value="${opt}">${this.capitalize(opt)}</option>`;
            } else {
                html += `<option value="${opt.value}">${opt.label}</option>`;
            }
        });

        select.innerHTML = html;

        if (keepSelection && currentValue) {
            select.value = currentValue;
        }
    }

    getFilters() {
        const filters = {};

        this.container.querySelectorAll('.filter-select').forEach(sel => {
            const key = sel.dataset.filter;
            const value = sel.value;
            if (value) {
                filters[key] = value;
            }
        });

        const searchInput = document.getElementById('filter-search');
        if (searchInput && searchInput.value.trim()) {
            filters.search = searchInput.value.trim();
        }

        return filters;
    }

    applyFilters() {
        const filters = this.getFilters();
        this.saveToURL(filters);
        this.onFilter(filters);
    }

    clearFilters() {
        this.container.querySelectorAll('.filter-select').forEach(sel => {
            sel.value = '';
        });

        const searchInput = document.getElementById('filter-search');
        if (searchInput) {
            searchInput.value = '';
        }

        this.applyFilters();
    }

    saveToURL(filters) {
        const url = new URL(window.location);

        // Clear existing filter params
        [...url.searchParams.keys()].forEach(key => {
            if (key.startsWith('f_') || key === 'search') {
                url.searchParams.delete(key);
            }
        });

        // Set new filter params
        Object.entries(filters).forEach(([key, value]) => {
            if (key === 'search') {
                url.searchParams.set('search', value);
            } else {
                url.searchParams.set(`f_${key}`, value);
            }
        });

        window.history.replaceState({}, '', url);
    }

    loadFromURL() {
        const url = new URL(window.location);

        url.searchParams.forEach((value, key) => {
            if (key.startsWith('f_')) {
                const filterId = key.substring(2);
                const select = document.getElementById(`filter-${filterId}`);
                if (select) {
                    select.value = value;
                }
            } else if (key === 'search') {
                const searchInput = document.getElementById('filter-search');
                if (searchInput) {
                    searchInput.value = value;
                }
            }
        });
    }

    /**
     * Update the result count display
     * @param {number} count - Number of results
     * @param {number} total - Total items (optional)
     */
    updateCount(count, total = null) {
        if (this.countElement) {
            if (total !== null && total !== count) {
                this.countElement.textContent = `${count} de ${total} resultados`;
            } else {
                this.countElement.textContent = `${count} resultados`;
            }
        }
    }

    capitalize(str) {
        return str.charAt(0).toUpperCase() + str.slice(1);
    }

    /**
     * Build query string for API calls
     * @param {object} extraParams - Additional params to include
     */
    buildQueryString(extraParams = {}) {
        const filters = this.getFilters();
        const params = new URLSearchParams(extraParams);

        Object.entries(filters).forEach(([key, value]) => {
            params.set(key, value);
        });

        return params.toString();
    }
}

// CSS Styles are injected when first FilterBar is created
(function () {
    if (document.getElementById('filter-bar-styles')) return;

    const style = document.createElement('style');
    style.id = 'filter-bar-styles';
    style.textContent = `
        .filter-bar {
            padding: 0.75rem;
            background: var(--bg-card, #fff);
            border-bottom: 1px solid var(--border-color, #dee2e6);
        }
        
        .filter-bar-content {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            align-items: center;
        }
        
        .filter-item {
            flex: 0 0 auto;
        }
        
        .filter-search {
            flex: 1 1 150px;
            min-width: 150px;
            max-width: 250px;
        }
        
        .filter-actions {
            margin-left: auto;
        }
        
        .filter-count {
            margin-top: 0.5rem;
            padding-top: 0.5rem;
            border-top: 1px dashed var(--border-color, #dee2e6);
        }
        
        .filter-select {
            min-width: 130px;
        }
        
        @media (max-width: 768px) {
            .filter-item {
                flex: 1 1 calc(50% - 0.5rem);
            }
            
            .filter-search {
                flex: 1 1 100%;
                max-width: none;
            }
        }
        
        [data-theme="dark"] .filter-bar {
            background: var(--bg-card, #1e293b);
        }
    `;
    document.head.appendChild(style);
})();
