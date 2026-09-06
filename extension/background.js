
chrome.runtime.onInstalled.addListener(() => {
  console.log('[ThreatLens AI Shield] Extension installed successfully.');
  chrome.storage.sync.set({
    threatlens_enabled: true,
    threatlens_api_url: 'https://threatlens-gen.vercel.app'
  });
});
