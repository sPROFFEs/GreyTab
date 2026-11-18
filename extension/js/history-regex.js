// Captured URLs can contain arbitrary text. Keep slow user patterns off the UI thread.
self.onmessage = ({data: {pattern, rows}}) => {
    try {
        const regex = new RegExp(pattern, 'i');
        self.postMessage({ids: rows.filter(row => regex.test(row.url)).map(row => row.id)});
    } catch (error) {
        self.postMessage({error: error.message});
    }
};
