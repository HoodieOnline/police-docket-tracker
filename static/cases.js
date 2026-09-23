const modal = document.getElementById('caseModal');
const newCaseBtn = document.getElementById('newCaseBtn');
const closeModalBtn = document.getElementById('closeModalBtn');
const cancelBtn = document.getElementById('cancelBtn');

if (newCaseBtn) {
  newCaseBtn.addEventListener('click', () => modal.classList.add('open'));
}
if (closeModalBtn) {
  closeModalBtn.addEventListener('click', () => modal.classList.remove('open'));
}
if (cancelBtn) {
  cancelBtn.addEventListener('click', () => modal.classList.remove('open'));
}
if (modal) {
  modal.addEventListener('click', (event) => {
    if (event.target === modal) modal.classList.remove('open');
  });
}
