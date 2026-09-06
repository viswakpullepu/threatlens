
document.addEventListener('DOMContentLoaded', () => {
  const toggle = document.getElementById('toggleEnabled');
  
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.sync) {
    chrome.storage.sync.get(['threatlens_enabled'], (res) => {
      if (res.threatlens_enabled !== undefined) {
        toggle.checked = res.threatlens_enabled;
      }
    });

    toggle.addEventListener('change', () => {
      chrome.storage.sync.set({ threatlens_enabled: toggle.checked });
    });
  }
});
