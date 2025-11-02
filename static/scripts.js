// Small frontend UX helpers for SecureFinTech
(function(){
  document.addEventListener('DOMContentLoaded', function(){
    // Auto-dismiss alerts after 5s
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach((a)=>{
      setTimeout(()=>{
        if (a && a.classList) a.classList.remove('show');
      }, 5000);
    });

    // Enable Bootstrap tooltips if present
    if (window.bootstrap) {
      const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
      tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
      });
    }
  });
})();