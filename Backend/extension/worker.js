import { pipeline, env } from 'https://cdn.jsdelivr.net/npm/@xenova/transformers@2.17.1';

// Configure environment for extension
env.allowLocalModels = false;
env.useBrowserCache = true;

let classifier;

// Listen for messages from the sidepanel
self.onmessage = async (e) => {
    const { action, text } = e.data;

    if (action === 'init') {
        try {
            classifier = await pipeline('text-classification', 'Xenova/distilbert-base-uncased-finetuned-sst-2-english', {
                progress_callback: (data) => {
                    // Send download progress back to UI
                    if (data.status === 'progress') {
                        self.postMessage({ status: 'loading', progress: data.progress });
                    }
                }
            });
            self.postMessage({ status: 'ready' });
        } catch (err) {
            self.postMessage({ status: 'error', message: err.message });
        }
    }

    if (action === 'classify') {
        if (!classifier) return;
        try {
            const output = await classifier(text);
            self.postMessage({ status: 'result', output });
        } catch (err) {
            self.postMessage({ status: 'error', message: err.message });
        }
    }
};