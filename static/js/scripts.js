/**
 * PhishGuard URL Detector
 * Client-side JavaScript for enhancing the user experience
 */

document.addEventListener('DOMContentLoaded', function() {
    // Form validation
    const urlForm = document.getElementById('urlForm');
    if (urlForm) {
        urlForm.addEventListener('submit', function(event) {
            const urlInput = document.getElementById('url');
            const url = urlInput.value.trim();
            
            // Basic URL validation - make sure there's some content
            if (!url) {
                event.preventDefault();
                showAlert('Please enter a URL to analyze', 'warning');
                return;
            }
            
            // Very basic URL format check - this is a simple client-side check,
            // the server will do more comprehensive validation
            if (!isValidURL(url)) {
                event.preventDefault();
                showAlert('Please enter a valid URL (e.g., https://example.com)', 'warning');
                return;
            }
            
            // Add loading indicator
            const submitButton = urlForm.querySelector('button[type="submit"]');
            submitButton.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span> Analyzing...';
            submitButton.disabled = true;
        });
    }
    
    // Show tooltips for any elements with data-bs-toggle="tooltip"
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Initialize any popovers
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function(popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });
});

/**
 * Basic URL validation function.
 * @param {string} url - The URL to validate.
 * @return {boolean} True if the URL is valid, false otherwise.
 */
function isValidURL(url) {
    // Add http:// if not present to make the URL parser work
    if (!url.match(/^[a-zA-Z]+:\/\//)) {
        url = 'http://' + url;
    }
    
    try {
        new URL(url);
        return true;
    } catch (e) {
        return false;
    }
}

/**
 * Show a Bootstrap alert.
 * @param {string} message - The message to display.
 * @param {string} type - The alert type (success, danger, warning, info).
 */
function showAlert(message, type = 'info') {
    // Create alert element
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
    alertDiv.role = 'alert';
    
    // Set alert content
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;
    
    // Find the flash message container or add to top of main container
    const container = document.querySelector('.alert-container') || document.querySelector('.container');
    if (container) {
        container.prepend(alertDiv);
        
        // Auto dismiss after 5 seconds
        setTimeout(() => {
            const bsAlert = new bootstrap.Alert(alertDiv);
            bsAlert.close();
        }, 5000);
    }
}
