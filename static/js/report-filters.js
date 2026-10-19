window.cveFilterSystem = function cveFilterSystem() {
  return {
    severityFilter: "all",
    sourceFilter: "all",
    searchQuery: "",
    sortBy: "severity",
    sortOrder: "desc",
    showKevOnly: false,
    cvssMin: 0,
    cvssMax: 10,
    currentPage: 1,
    perPage: 50,
    expandedCve: null,
    showAdvancedFilters: false,
    allCves: [],
    filteredCves: [],
    stats: {
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      unknown: 0,
      kev: 0,
    },

    initCves() {
      this.$nextTick(() => {
        const items = document.querySelectorAll(".cve-data-item");
        this.allCves = Array.from(items).map((el) => ({
          id: el.dataset.cveId || "",
          severity: (el.dataset.severity || "UNKNOWN").toUpperCase().trim(),
          source: (el.dataset.source || "").trim(),
          cvss: parseFloat(el.dataset.cvss) || 0,
          kev: el.dataset.kev === "true",
          technology: el.dataset.technology || "",
          description: el.dataset.description || "",
          element: el,
        }));

        this.stats.total = this.allCves.length;
        this.stats.critical = this.allCves.filter((cve) => cve.severity === "CRITICAL").length;
        this.stats.high = this.allCves.filter((cve) => cve.severity === "HIGH").length;
        this.stats.medium = this.allCves.filter((cve) => cve.severity === "MEDIUM").length;
        this.stats.low = this.allCves.filter((cve) => cve.severity === "LOW").length;
        this.stats.unknown = this.allCves.filter((cve) => cve.severity === "UNKNOWN").length;
        this.stats.kev = this.allCves.filter((cve) => cve.kev).length;
        this.applyFilters();
      });
    },

    applyFilters() {
      let filtered = [...this.allCves];

      if (this.severityFilter !== "all") {
        filtered = filtered.filter((cve) => cve.severity === this.severityFilter);
      }
      if (this.sourceFilter !== "all") {
        filtered =
          this.sourceFilter === "Tech"
            ? filtered.filter((cve) => cve.technology)
            : filtered.filter((cve) => cve.source === this.sourceFilter);
      }
      if (this.showKevOnly) {
        filtered = filtered.filter((cve) => cve.kev);
      }
      filtered = filtered.filter(
        (cve) => cve.cvss >= this.cvssMin && cve.cvss <= this.cvssMax,
      );

      if (this.searchQuery.trim()) {
        const query = this.searchQuery.toLowerCase().trim();
        filtered = filtered.filter(
          (cve) =>
            cve.id.toLowerCase().includes(query) ||
            cve.description.toLowerCase().includes(query) ||
            cve.technology.toLowerCase().includes(query),
        );
      }

      const severityOrder = {
        CRITICAL: 0,
        HIGH: 1,
        MEDIUM: 2,
        LOW: 3,
        UNKNOWN: 4,
      };
      filtered.sort((left, right) => {
        let comparison = 0;
        switch (this.sortBy) {
          case "severity":
            comparison = severityOrder[left.severity] - severityOrder[right.severity];
            break;
          case "cvss":
            comparison = right.cvss - left.cvss;
            break;
          case "id":
            comparison = left.id.localeCompare(right.id);
            break;
          default:
            comparison = 0;
        }
        return this.sortOrder === "desc" ? comparison : -comparison;
      });

      this.filteredCves = filtered;
      this.currentPage = 1;
      this.updatePage();
    },

    updatePage() {
      const pageStart = (this.currentPage - 1) * this.perPage;
      const pageEnd = pageStart + this.perPage;

      this.allCves.forEach((cve) => {
        const indexInFiltered = this.filteredCves.indexOf(cve);
        const isInPage =
          indexInFiltered >= pageStart && indexInFiltered < pageEnd;
        if (cve.element) {
          cve.element.style.display =
            indexInFiltered >= 0 && isInPage ? "" : "none";
        }
      });
    },

    get totalPages() {
      return Math.ceil(this.filteredCves.length / this.perPage);
    },

    get visibleCount() {
      const pageStart = (this.currentPage - 1) * this.perPage;
      return Math.min(this.perPage, this.filteredCves.length - pageStart);
    },

    get activeFiltersCount() {
      let count = 0;
      if (this.severityFilter !== "all") count += 1;
      if (this.sourceFilter !== "all") count += 1;
      if (this.showKevOnly) count += 1;
      if (this.cvssMin > 0 || this.cvssMax < 10) count += 1;
      if (this.searchQuery.trim()) count += 1;
      return count;
    },

    clearAllFilters() {
      this.severityFilter = "all";
      this.sourceFilter = "all";
      this.searchQuery = "";
      this.showKevOnly = false;
      this.cvssMin = 0;
      this.cvssMax = 10;
      this.applyFilters();
    },

    toggleSeverity(severity) {
      this.severityFilter = this.severityFilter === severity ? "all" : severity;
      this.applyFilters();
    },

    setPerPage(num) {
      this.perPage = num;
      this.currentPage = 1;
      this.updatePage();
    },

    nextPage() {
      if (this.currentPage < this.totalPages) {
        this.currentPage += 1;
        this.updatePage();
      }
    },

    prevPage() {
      if (this.currentPage > 1) {
        this.currentPage -= 1;
        this.updatePage();
      }
    },

    goToPage(page) {
      this.currentPage = Math.max(1, Math.min(page, this.totalPages));
      this.updatePage();
    },
  };
};
