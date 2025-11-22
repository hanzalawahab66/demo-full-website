// Lightweight multilingual support without external services
(function(){
  const SUPPORTED = [
    { code: 'en', label: 'English', flag: 'us' },
    { code: 'ko', label: '한국어', flag: 'kr' },
    { code: 'ar', label: 'العربية', flag: 'sa' },
    { code: 'fr', label: 'Français', flag: 'fr' }
  ];

  // Minimal shared dictionary for common UI strings.
  // Pages can add more via window.__LANG_EXTENSIONS.
  const DICTIONARY = {
    en: {
      'sign-in': 'Sign In',
      'sign-up': 'Sign Up',
      'search-placeholder': 'Identification Number / Product Number',
      'offers-count': 'Search Inventory'
    },
    ko: {
      'sign-in': '로그인',
      'sign-up': '회원가입',
      'search-placeholder': '식별 번호 / 제품 번호',
      'offers-count': '재고 검색'
    },
    ar: {
      'sign-in': 'تسجيل الدخول',
      'sign-up': 'إنشاء حساب',
      'search-placeholder': 'رقم التعريف / رقم المنتج',
      'offers-count': 'بحث في المخزون'
    },
    fr: {
      'sign-in': 'Se connecter',
      'sign-up': "S'inscrire",
      'search-placeholder': 'Numéro d’identification / Numéro de produit',
      'offers-count': "Rechercher l’inventaire"
    }
  };

  function mergeExtensions(dict){
    try {
      const ext = window.__LANG_EXTENSIONS || {};
      Object.keys(ext).forEach(lang => {
        dict[lang] = Object.assign({}, dict[lang] || {}, ext[lang] || {});
      });
    } catch(_){ /* noop */ }
    return dict;
  }

  function updateLabel(lang){
    const labelEl = document.querySelector('#languageToggle span');
    const label = SUPPORTED.find(l => l.code === lang)?.label || 'English';
    if (labelEl) labelEl.textContent = label;
  }

  function setDirection(lang){
    document.body.setAttribute('dir', lang === 'ar' ? 'rtl' : 'ltr');
  }

  function applyTranslations(lang){
    const dict = mergeExtensions(Object.assign({}, DICTIONARY));
    const fallback = dict.en || {};
    const table = dict[lang] || fallback;

    const nodes = document.querySelectorAll('[data-text]');
    nodes.forEach(node => {
      const key = node.getAttribute('data-text');
      const val = table[key] || fallback[key];
      if (!val) return;
      if (node.tagName === 'INPUT' || node.tagName === 'TEXTAREA') {
        node.setAttribute('placeholder', val);
      } else {
        node.textContent = val;
      }
    });
  }

  function applyLanguage(lang){
    setDirection(lang);
    updateLabel(lang);
    localStorage.setItem('__site_lang', lang);
    applyTranslations(lang);
  }

  function wireDropdown(){
    const toggleBtn = document.getElementById('languageToggle');
    const menu = document.getElementById('languageDropdown');
    if (!toggleBtn || !menu) return;
    toggleBtn.addEventListener('click', (e) => { e.stopPropagation(); menu.classList.toggle('hidden'); });
    document.addEventListener('click', (e) => {
      if (!menu.contains(e.target) && e.target !== toggleBtn) menu.classList.add('hidden');
    });
    menu.querySelectorAll('[data-lang]').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const lang = btn.getAttribute('data-lang');
        applyLanguage(lang);
        menu.classList.add('hidden');
      });
    });
  }

  document.addEventListener('DOMContentLoaded', () => {
    wireDropdown();
    const saved = localStorage.getItem('__site_lang') || 'en';
    applyLanguage(saved);
  });

  window.setSiteLanguage = applyLanguage;
})();