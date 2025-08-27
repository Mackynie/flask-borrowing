document.addEventListener('DOMContentLoaded', function () {
  const searchInput = document.getElementById('searchInput');
  const dateFilter = document.getElementById('dateFilter');
  const statusFilter = document.getElementById('statusFilter');

  function filterTable() {
    const rows = document.querySelectorAll('#historyTable tbody tr');
    const searchTerm = searchInput.value.toLowerCase();
    const dateValue = dateFilter.value;
    const statusValue = statusFilter.value;

    rows.forEach(row => {
      const cells = row.querySelectorAll('td');
      const rowText = row.textContent.toLowerCase();
      const rowDate = cells[3]?.textContent.trim().split(' ')[0]; // extract date only
      const rowStatus = cells[4]?.textContent.trim();

      const matchesSearch = rowText.includes(searchTerm);
      const matchesDate = !dateValue || rowDate === dateValue;
      const matchesStatus = !statusValue || rowStatus === statusValue;

      if (matchesSearch && matchesDate && matchesStatus) {
        row.style.display = '';
      } else {
        row.style.display = 'none';
      }
    });
  }

  searchInput.addEventListener('input', filterTable);
  dateFilter.addEventListener('change', filterTable);
  statusFilter.addEventListener('change', filterTable);
});

function exportFilteredToPDF() {
  const source = document.getElementById('exportSection');

  // Clone node so we don't alter live DOM
  const cloned = source.cloneNode(true);
  cloned.style.display = 'block';

  // Optional: wrap in clean container
  const container = document.createElement('div');
  container.appendChild(cloned);

  const opt = {
    margin:       0.5,
    filename:     'BARMA-History-Report.pdf',
    image:        { type: 'jpeg', quality: 0.98 },
    html2canvas:  { scale: 2 },
    jsPDF:        { unit: 'in', format: 'letter', orientation: 'portrait' }
  };

  html2pdf().set(opt).from(container).save();
}


function exportFilteredToWord() {
  const exportSection = document.getElementById('exportSection');
  const style = `
    <style>
      body { font-family: 'Segoe UI', sans-serif; font-size: 14px; color: #000; }
      table { width: 100%; border-collapse: collapse; }
      th, td { border: 1px solid #000; padding: 8px; text-align: center; }
      th { background-color: #ddd; font-weight: bold; }
      h4 { margin-bottom: 0.5rem; }
    </style>
  `;

  const header = `
    <html xmlns:o='urn:schemas-microsoft-com:office:office'
          xmlns:w='urn:schemas-microsoft-com:office:word'
          xmlns='http://www.w3.org/TR/REC-html40'>
    <head><meta charset='utf-8'><title>BARMA Export</title>${style}</head><body>`;
  const footer = '</body></html>';

  const html = header + exportSection.innerHTML + footer;
  const blob = new Blob(['\ufeff', html], { type: 'application/msword' });
  const url = URL.createObjectURL(blob);

  const link = document.createElement('a');
  link.href = url;
  link.download = 'BARMA-History-Report.doc';
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

