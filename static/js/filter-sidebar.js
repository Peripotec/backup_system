/**
 * FilterSidebar Component - Enterprise UI
 * 
 * ES6 Class-based filter panel with persistence and callbacks.
 * Follows Jira/ServiceNow/Splunk patterns.
 * 
 * @example
 * const filters = new FilterSidebar({
 *     container: '#filter-container',
 *     sections: [
 *         { id: 'vendor', label: 'Vendor', icon: '🏭', type: 'multiselect', options: [...] }
 *     ],
 *     onChange: (filters) => { loadData(filters); },
 *     storageKey: 'dashboard-filters'
 * });
 */

class FilterSidebar {
    /**
     * Create a FilterSidebar instance
     * @param {Object} options - Configuration options
     * @param {string|HTMLElement} options.container - Container selector or element
     * @param {Array} options.sections - Filter sections configuration
     * @param {Function} options.onChange - Callback when filters change
     * @param {string} [options.storageKey] - Key for sessionStorage persistence
     * @param {boolean} [options.collapsed] - Start collapsed
     */
    constructor(options) {
        this.options = Object.assign({
            container: null,
            sections: [],
            onChange: null,
            storageKey: null,
            collapsed: false,
            title: 'Filtros',
            applyButtonText: 'Aplicar',
            clearButtonText: 'Limpiar'
        }, options);

        this.container = typeof this.options.container === 'string'
            ? document.querySelector(this.options.container)
            : this.options.container;

        if (!this.container) {
            console.error('FilterSidebar: Container not found');
            return;
        }

        this.values = {};
        this.isCollapsed = this.options.collapsed;

        // Load saved state from storage
        this._loadFromStorage();

        this.render();
        this._bindEvents();
    }

    /**
     * Render the filter sidebar
     */
    render() {
        if (!this.container) return;

        const collapsedClass = this.isCollapsed ? 'filter-layout--collapsed' : '';
        const activeCount = this._getActiveFilterCount();

        let html = `
            <div class="filter-layout ${collapsedClass}">
                <aside class="filter-sidebar">
                    <div class="filter-sidebar__header">
                        <span class="filter-sidebar__title">
                            ≡ ${this.options.title}
                            ${activeCount > 0 ? `<span class="filter-active-badge">${activeCount}</span>` : ''}
                        </span>
                        <button class="filter-sidebar__toggle" title="Ocultar filtros" data-action="toggle">
                            ◀
                        </button>
                    </div>
                    <div class="filter-sidebar__body">
                        ${this._renderSections()}
                        <div class="filter-actions">
                            <button class="filter-btn filter-btn--primary" data-action="apply">
                                ${this.options.applyButtonText}
                            </button>
                            <button class="filter-btn filter-btn--secondary" data-action="clear">
                                ${this.options.clearButtonText}
                            </button>
                        </div>
                    </div>
                </aside>
                <div class="filter-layout__content" id="filter-content">
                    <button class="filter-toggle-collapsed" data-action="toggle" title="Mostrar filtros">
                        ▶
                    </button>
                    <!-- Content will be injected here -->
                </div>
            </div>
        `;

        this.container.innerHTML = html;

        // Find content area for external use
        this.contentArea = this.container.querySelector('#filter-content');
    }

    /**
     * Render all filter sections
     * @private
     */
    _renderSections() {
        return this.options.sections.map(section => {
            let controlHtml = '';
            const currentValue = this.values[section.id];

            switch (section.type) {
                case 'select':
                    controlHtml = this._renderSelect(section, currentValue);
                    break;
                case 'multiselect':
                    controlHtml = this._renderMultiselect(section, currentValue);
                    break;
                case 'search':
                    controlHtml = this._renderSearch(section, currentValue);
                    break;
                default:
                    controlHtml = this._renderSelect(section, currentValue);
            }

            return `
                <div class="filter-section" data-filter-id="${section.id}">
                    <div class="filter-section__header">
                        <span class="filter-section__icon">${section.icon || ''}</span>
                        <span>${section.label}</span>
                    </div>
                    ${controlHtml}
                </div>
            `;
        }).join('');
    }

    /**
     * Render a select dropdown
     * @private
     */
    _renderSelect(section, currentValue) {
        const activeClass = currentValue ? 'filter-select--active' : '';
        const options = (section.options || []).map(opt => {
            const value = typeof opt === 'object' ? opt.value : opt;
            const label = typeof opt === 'object' ? opt.label : opt;
            const selected = currentValue === value ? 'selected' : '';
            return `<option value="${this._escapeHtml(value)}" ${selected}>${this._escapeHtml(label)}</option>`;
        }).join('');

        return `
            <select class="filter-select ${activeClass}" data-filter="${section.id}">
                <option value="">${section.placeholder || 'Todos'}</option>
                ${options}
            </select>
        `;
    }

    /**
     * Render a multiselect checkbox group
     * @private
     */
    _renderMultiselect(section, currentValues) {
        const values = currentValues || [];
        const checkboxes = (section.options || []).map(opt => {
            const value = typeof opt === 'object' ? opt.value : opt;
            const label = typeof opt === 'object' ? opt.label : opt;
            const count = typeof opt === 'object' ? opt.count : null;
            const checked = values.includes(value) ? 'checked' : '';

            return `
                <label class="filter-checkbox">
                    <input type="checkbox" value="${this._escapeHtml(value)}" ${checked} data-filter="${section.id}">
                    <span class="filter-checkbox__label">${this._escapeHtml(label)}</span>
                    ${count !== null ? `<span class="filter-checkbox__count">(${count})</span>` : ''}
                </label>
            `;
        }).join('');

        return `<div class="filter-checkbox-group">${checkboxes}</div>`;
    }

    /**
     * Render a search input
     * @private
     */
    _renderSearch(section, currentValue) {
        return `
            <input type="text" 
                   class="filter-select" 
                   data-filter="${section.id}"
                   placeholder="${section.placeholder || 'Buscar...'}"
                   value="${this._escapeHtml(currentValue || '')}">
        `;
    }

    /**
     * Bind event listeners
     * @private
     */
    _bindEvents() {
        if (!this.container) return;

        // Event delegation
        this.container.addEventListener('click', (e) => {
            const action = e.target.closest('[data-action]')?.dataset.action;

            switch (action) {
                case 'toggle':
                    this.toggle();
                    break;
                case 'apply':
                    this._collectValues();
                    this._saveToStorage();
                    this._triggerChange();
                    break;
                case 'clear':
                    this.clear();
                    break;
            }
        });

        // Auto-apply on change for selects
        this.container.addEventListener('change', (e) => {
            const filterEl = e.target.closest('[data-filter]');
            if (filterEl) {
                this._collectValues();
                this._updateActiveStyles();
                // Auto-apply on select change
                if (filterEl.tagName === 'SELECT') {
                    this._saveToStorage();
                    this._triggerChange();
                }
            }
        });

        // Search on Enter key
        this.container.addEventListener('keyup', (e) => {
            if (e.key === 'Enter') {
                const filterEl = e.target.closest('[data-filter]');
                if (filterEl && filterEl.tagName === 'INPUT') {
                    this._collectValues();
                    this._saveToStorage();
                    this._triggerChange();
                }
            }
        });
    }

    /**
     * Collect current filter values from DOM
     * @private
     */
    _collectValues() {
        this.values = {};

        // Selects and text inputs
        this.container.querySelectorAll('select[data-filter], input[type="text"][data-filter]').forEach(el => {
            const id = el.dataset.filter;
            const value = el.value.trim();
            if (value) {
                this.values[id] = value;
            }
        });

        // Checkboxes (multiselect)
        const checkboxGroups = {};
        this.container.querySelectorAll('input[type="checkbox"][data-filter]:checked').forEach(el => {
            const id = el.dataset.filter;
            if (!checkboxGroups[id]) checkboxGroups[id] = [];
            checkboxGroups[id].push(el.value);
        });
        Object.assign(this.values, checkboxGroups);
    }

    /**
     * Update active styles on controls
     * @private
     */
    _updateActiveStyles() {
        this.container.querySelectorAll('select[data-filter]').forEach(el => {
            el.classList.toggle('filter-select--active', !!el.value);
        });

        // Update badge
        const badge = this.container.querySelector('.filter-active-badge');
        const count = this._getActiveFilterCount();
        if (badge) {
            badge.textContent = count;
            badge.style.display = count > 0 ? 'inline-flex' : 'none';
        }
    }

    /**
     * Get count of active filters
     * @private
     */
    _getActiveFilterCount() {
        let count = 0;
        for (const key in this.values) {
            const val = this.values[key];
            if (Array.isArray(val)) {
                count += val.length;
            } else if (val) {
                count++;
            }
        }
        return count;
    }

    /**
     * Toggle sidebar collapse
     */
    toggle() {
        this.isCollapsed = !this.isCollapsed;
        const layout = this.container.querySelector('.filter-layout');
        if (layout) {
            layout.classList.toggle('filter-layout--collapsed', this.isCollapsed);
        }
        this._saveToStorage();
    }

    /**
     * Clear all filters
     */
    clear() {
        this.values = {};

        // Reset selects
        this.container.querySelectorAll('select[data-filter]').forEach(el => {
            el.value = '';
            el.classList.remove('filter-select--active');
        });

        // Reset checkboxes
        this.container.querySelectorAll('input[type="checkbox"][data-filter]').forEach(el => {
            el.checked = false;
        });

        // Reset text inputs
        this.container.querySelectorAll('input[type="text"][data-filter]').forEach(el => {
            el.value = '';
        });

        this._updateActiveStyles();
        this._saveToStorage();
        this._triggerChange();
    }

    /**
     * Get current filter values
     * @returns {Object} Current filter values
     */
    getValues() {
        return { ...this.values };
    }

    /**
     * Set filter values programmatically
     * @param {Object} values - Filter values to set
     */
    setValues(values) {
        this.values = { ...values };
        this.render();
        this._bindEvents();
    }

    /**
     * Get content area element for injecting content
     * @returns {HTMLElement}
     */
    getContentArea() {
        return this.contentArea;
    }

    /**
     * Trigger onChange callback
     * @private
     */
    _triggerChange() {
        if (this.options.onChange) {
            this.options.onChange(this.getValues());
        }
    }

    /**
     * Save state to sessionStorage
     * @private
     */
    _saveToStorage() {
        if (!this.options.storageKey) return;

        try {
            const state = {
                values: this.values,
                collapsed: this.isCollapsed
            };
            sessionStorage.setItem(this.options.storageKey, JSON.stringify(state));
        } catch (e) {
            console.warn('FilterSidebar: Could not save to storage', e);
        }
    }

    /**
     * Load state from sessionStorage
     * @private
     */
    _loadFromStorage() {
        if (!this.options.storageKey) return;

        try {
            const saved = sessionStorage.getItem(this.options.storageKey);
            if (saved) {
                const state = JSON.parse(saved);
                this.values = state.values || {};
                this.isCollapsed = state.collapsed || false;
            }
        } catch (e) {
            console.warn('FilterSidebar: Could not load from storage', e);
        }
    }

    /**
     * Update options for a section (useful for dynamic options)
     * @param {string} sectionId - Section ID
     * @param {Array} options - New options
     */
    updateSectionOptions(sectionId, options) {
        const section = this.options.sections.find(s => s.id === sectionId);
        if (section) {
            section.options = options;
            this.render();
            this._bindEvents();
        }
    }

    /**
     * Escape HTML to prevent XSS
     * @private
     */
    _escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }
}

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = FilterSidebar;
}
