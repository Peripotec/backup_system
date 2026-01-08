/**
 * TreeView Component - Enterprise UI
 * 
 * ES6 Class-based collapsible tree for hierarchical data display.
 * Follows CMDB/NetBox patterns with accessibility support.
 * 
 * @example
 * const tree = new TreeView({
 *     container: '#auto-groups-container',
 *     data: [
 *         { name: 'HP', icon: '🏭', children: [...] }
 *     ],
 *     onAction: (action, device) => { ... }
 * });
 */

class TreeView {
    /**
     * Create a TreeView instance
     * @param {Object} options - Configuration options
     * @param {string|HTMLElement} options.container - Container selector or element
     * @param {string} [options.sectionTitle] - Section header title
     * @param {string} [options.sectionIcon] - Section header icon
     * @param {Function} [options.onAction] - Callback for device actions
     * @param {Function} [options.onExpand] - Callback when node expands
     */
    constructor(options) {
        this.options = Object.assign({
            container: null,
            sectionTitle: '',
            sectionIcon: '📁',
            onAction: null,
            onExpand: null,
            emptyText: 'No hay elementos',
            loadingText: 'Cargando...'
        }, options);

        this.container = typeof this.options.container === 'string'
            ? document.querySelector(this.options.container)
            : this.options.container;

        if (!this.container) {
            console.error('TreeView: Container not found');
            return;
        }

        this.data = [];
        this._bindEvents();
    }

    /**
     * Set data and render the tree
     * @param {Array} data - Tree data array
     */
    setData(data) {
        this.data = data || [];
        this.render();
    }

    /**
     * Render the tree view
     */
    render() {
        if (!this.container) return;

        if (this.data.length === 0) {
            this.container.innerHTML = `
                <div class="tree-view__empty">${this.options.emptyText}</div>
            `;
            return;
        }

        let html = '<div class="tree-view">';

        // Section header if provided
        if (this.options.sectionTitle) {
            html += `
                <div class="tree-view__section-header">
                    <span class="tree-view__section-icon">${this.options.sectionIcon}</span>
                    <span>${this.options.sectionTitle}</span>
                </div>
            `;
        }

        // Render nodes
        this.data.forEach((node, index) => {
            html += this._renderNode(node, index);
        });

        html += '</div>';
        this.container.innerHTML = html;
    }

    /**
     * Render a single tree node
     * @private
     */
    _renderNode(node, index) {
        const vendorClass = this._getVendorClass(node.name);
        const iconClass = this._getIconClass(node.name);
        const childCount = node.children ? node.children.length : 0;

        let html = `
            <div class="tree-view__node ${vendorClass}" data-node-index="${index}">
                <div class="tree-view__node-header" 
                     role="button" 
                     tabindex="0"
                     aria-expanded="false"
                     aria-label="${node.name}, ${childCount} dispositivos">
                    <span class="tree-view__toggle">▶</span>
                    <span class="tree-view__node-icon ${iconClass}">${node.icon || '📦'}</span>
                    <span class="tree-view__node-label">${this._escapeHtml(node.name)}</span>
                    <span class="tree-view__node-count">${childCount}</span>
                </div>
                <div class="tree-view__children" role="group">
        `;

        // Render children (devices)
        if (node.children && node.children.length > 0) {
            node.children.forEach(device => {
                html += this._renderDevice(device);
            });
        }

        html += `
                </div>
            </div>
        `;

        return html;
    }

    /**
     * Render a device item (leaf node)
     * @private
     */
    _renderDevice(device) {
        const sysname = device.sysname || device.hostname || 'N/A';
        const ip = device.ip || device.hostname || '';
        const grupo = device.grupo || '';

        return `
            <div class="tree-view__device" data-sysname="${this._escapeHtml(sysname)}" data-vendor="${this._escapeHtml(device.vendor || '')}">
                <span class="tree-view__device-name">${this._escapeHtml(sysname)}</span>
                <span class="tree-view__device-ip">${this._escapeHtml(ip)}</span>
                <span class="tree-view__device-grupo">${this._escapeHtml(grupo)}</span>
                <div class="tree-view__device-actions">
                    <button class="tree-view__action-btn tree-view__action-btn--primary" 
                            data-action="files" 
                            title="Ver archivos">📁</button>
                    <button class="tree-view__action-btn tree-view__action-btn--success" 
                            data-action="backup" 
                            title="Ejecutar backup">🔄</button>
                    <button class="tree-view__action-btn" 
                            data-action="diff" 
                            title="Ver diferencias">📝</button>
                </div>
            </div>
        `;
    }

    /**
     * Bind event listeners using event delegation
     * @private
     */
    _bindEvents() {
        if (!this.container) return;

        // Event delegation for all tree interactions
        this.container.addEventListener('click', (e) => {
            // Node header click - expand/collapse
            const header = e.target.closest('.tree-view__node-header');
            if (header) {
                this._toggleNode(header.parentElement);
                return;
            }

            // Action button click
            const actionBtn = e.target.closest('.tree-view__action-btn');
            if (actionBtn) {
                const action = actionBtn.dataset.action;
                const deviceEl = actionBtn.closest('.tree-view__device');
                if (deviceEl && this.options.onAction) {
                    const sysname = deviceEl.dataset.sysname;
                    const vendor = deviceEl.dataset.vendor;
                    this.options.onAction(action, { sysname, vendor });
                }
                return;
            }
        });

        // Keyboard support
        this.container.addEventListener('keydown', (e) => {
            const header = e.target.closest('.tree-view__node-header');
            if (header && (e.key === 'Enter' || e.key === ' ')) {
                e.preventDefault();
                this._toggleNode(header.parentElement);
            }
        });
    }

    /**
     * Toggle node expand/collapse
     * @private
     */
    _toggleNode(node) {
        if (!node) return;

        const isExpanded = node.classList.contains('tree-view__node--expanded');
        const header = node.querySelector('.tree-view__node-header');

        if (isExpanded) {
            node.classList.remove('tree-view__node--expanded');
            header?.setAttribute('aria-expanded', 'false');
        } else {
            node.classList.add('tree-view__node--expanded');
            header?.setAttribute('aria-expanded', 'true');

            // Call onExpand callback
            if (this.options.onExpand) {
                const index = parseInt(node.dataset.nodeIndex, 10);
                this.options.onExpand(this.data[index], index);
            }
        }
    }

    /**
     * Expand all nodes
     */
    expandAll() {
        this.container.querySelectorAll('.tree-view__node').forEach(node => {
            node.classList.add('tree-view__node--expanded');
            node.querySelector('.tree-view__node-header')?.setAttribute('aria-expanded', 'true');
        });
    }

    /**
     * Collapse all nodes
     */
    collapseAll() {
        this.container.querySelectorAll('.tree-view__node').forEach(node => {
            node.classList.remove('tree-view__node--expanded');
            node.querySelector('.tree-view__node-header')?.setAttribute('aria-expanded', 'false');
        });
    }

    /**
     * Show loading state
     */
    showLoading() {
        if (!this.container) return;
        this.container.innerHTML = `
            <div class="tree-view__loading">
                <span class="tree-view__loading-spinner"></span>
                ${this.options.loadingText}
            </div>
        `;
    }

    /**
     * Get vendor-specific CSS class
     * @private
     */
    _getVendorClass(name) {
        const n = (name || '').toLowerCase();
        if (n.includes('hp') || n.includes('comware')) return 'tree-view__node--hp';
        if (n.includes('huawei')) return 'tree-view__node--huawei';
        if (n.includes('zte')) return 'tree-view__node--zte';
        if (n.includes('cisco')) return 'tree-view__node--cisco';
        if (n.includes('mikrotik')) return 'tree-view__node--mikrotik';
        return '';
    }

    /**
     * Get icon CSS class
     * @private
     */
    _getIconClass(name) {
        const n = (name || '').toLowerCase();
        if (n.includes('hp') || n.includes('comware')) return 'tree-view__node-icon--hp';
        if (n.includes('huawei')) return 'tree-view__node-icon--huawei';
        if (n.includes('zte')) return 'tree-view__node-icon--zte';
        if (n.includes('cisco')) return 'tree-view__node-icon--cisco';
        if (n.includes('mikrotik')) return 'tree-view__node-icon--mikrotik';
        return 'tree-view__node-icon--default';
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
    module.exports = TreeView;
}
