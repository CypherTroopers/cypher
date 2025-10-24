(function () {
  const doc = document;
  const win = window;

  const defaultBrand = {
    href: 'https://funoncypherium.org/',
    label: 'Fun on Cypherium'
  };

  function defaultOriginFor(port) {
    if (!win.location) {
      return `http://localhost:${port}`;
    }
    const protocol = win.location.protocol || 'http:';
    const hostname = win.location.hostname || 'localhost';
    return `${protocol}//${hostname}:${port}`;
  }

  const serviceBases = Object.assign({
    freetoken: defaultOriginFor(4200),
    ranking: defaultOriginFor(4300),
    secretWallet: defaultOriginFor(4400)
  }, win.MENU_SERVICE_BASES || {});

  const servicePaths = Object.assign({
    freetoken: '/',
    ranking: '/ranking',
    secretWallet: '/wallet'
  }, win.MENU_SERVICE_PATHS || {});

  function buildServiceUrl(serviceKey) {
    const base = serviceBases[serviceKey] || win.location.origin;
    const path = servicePaths[serviceKey] || '/';
    try {
      return new URL(path, base).toString();
    } catch (err) {
      console.warn(`Failed to build URL for ${serviceKey}:`, err);
      return path;
    }
  }

  const defaultLinks = [
    { label: 'Token Generator', href: buildServiceUrl('freetoken'), match: '/' },
    { label: 'Bridge', href: 'https://funoncypherium.org/bridge', target: '_blank', rel: 'noreferrer noopener' },
    { label: 'Wallet Rank', href: buildServiceUrl('ranking'), target: '_blank', rel: 'noreferrer noopener', match: '/ranking' },
    { label: 'PupSwap🐶', href: 'https://pupswap.org/', target: '_blank', rel: 'noreferrer noopener' },
    { label: 'SecretWallet(TEST)', href: buildServiceUrl('secretWallet'), target: '_blank', rel: 'noreferrer noopener', match: '/wallet' },
    { label: 'Add Official RPC', type: 'action', action: 'addCypheriumRPC' }
  ];

  function ensureAddCypheriumRPC() {
    if (typeof win.addCypheriumRPC === 'function') {
      return;
    }

    win.addCypheriumRPC = async function addCypheriumRPC() {
      if (typeof win.ethereum === 'undefined') {
        win.alert('MetaMask is not detected. Please install it first.');
        return;
      }

      try {
        await win.ethereum.request({
          method: 'wallet_addEthereumChain',
          params: [{
            chainId: '0x3F26',
            chainName: 'Cypherium Mainnet',
            nativeCurrency: {
              name: 'CPH',
              symbol: 'CPH',
              decimals: 18
            },
            rpcUrls: ['https://pubnodes.cypherium.io/rpc'],
            blockExplorerUrls: ['https://cypherium.tryethernal.com/overview']
          }]
        });
        win.alert('Cypherium Mainnet RPC has been added to your wallet!');
      } catch (error) {
        console.error('Error adding network:', error);
        win.alert(`Failed to add network: ${error.message}`);
      }
    };
  }

  function normalizePath(path) {
    if (!path) return '';
    try {
      const url = new URL(path, win.location.origin);
      path = url.pathname;
    } catch (_) {
      // ignore
    }
    if (path === '/') return '/';
    return path.replace(/\/+$/, '');
  }

  function isActiveLink(linkConfig, activePath) {
    if (!activePath) return false;
    if (linkConfig.match) {
      return normalizePath(linkConfig.match) === normalizePath(activePath);
    }
    if (!linkConfig.href) {
      return false;
    }
    try {
      const url = new URL(linkConfig.href, win.location.origin);
      if (url.origin !== win.location.origin) {
        return false;
      }
      return normalizePath(url.pathname) === normalizePath(activePath);
    } catch (_) {
      return false;
    }
  }

  function createToggle(className, aria) {
    const button = doc.createElement('button');
    button.type = 'button';
    button.className = className;
    if (aria) {
      Object.entries(aria).forEach(([key, value]) => {
        button.setAttribute(key, value);
      });
    }
    for (let i = 0; i < 3; i += 1) {
      button.appendChild(doc.createElement('span'));
    }
    return button;
  }

  function buildMenu() {
    if (doc.querySelector('.main-nav')) {
      return;
    }

    const brand = Object.assign({}, defaultBrand, win.MENU_BRAND || {});
    const links = Array.isArray(win.MENU_CONFIG) && win.MENU_CONFIG.length
      ? win.MENU_CONFIG
      : defaultLinks;

    const activePath = normalizePath(win.MENU_ACTIVE_PATH || win.location.pathname || '/');

    ensureAddCypheriumRPC();

    const nav = doc.createElement('nav');
    nav.className = 'main-nav';

    const overlayId = 'menuOverlay';
    const openToggle = createToggle('menu-toggle', {
      'aria-label': 'Open navigation',
      'aria-expanded': 'false',
      'aria-controls': overlayId
    });

    nav.appendChild(openToggle);
    doc.body.appendChild(nav);

    const overlay = doc.createElement('div');
    overlay.id = overlayId;
    overlay.className = 'menu-overlay';
    overlay.setAttribute('aria-hidden', 'true');

    const overlayInner = doc.createElement('div');
    overlayInner.className = 'overlay-inner';

    const header = doc.createElement('div');
    header.className = 'overlay-header';

    const brandLink = doc.createElement('a');
    brandLink.className = 'overlay-brand';
    brandLink.href = brand.href;
    brandLink.textContent = brand.label;
    header.appendChild(brandLink);

    const closeToggle = createToggle('menu-toggle close-toggle', {
      'aria-label': 'Close navigation'
    });

    header.appendChild(closeToggle);
    overlayInner.appendChild(header);

    const linksContainer = doc.createElement('div');
    linksContainer.className = 'overlay-links';

    links.forEach((item) => {
      const type = item.type || 'link';
      let element;
      if (type === 'action') {
        element = doc.createElement('button');
        element.type = 'button';
        element.className = 'overlay-button';
        element.addEventListener('click', () => {
          setMenuState(false);
          const actionName = item.action;
          if (actionName && typeof win[actionName] === 'function') {
            win[actionName]();
          }
        });
      } else {
        element = doc.createElement('a');
        element.href = item.href;
        if (item.target) {
          element.target = item.target;
        }
        if (item.rel) {
          element.rel = item.rel;
        }
      }

      element.classList.add('overlay-link');
      element.textContent = item.label;

      if (isActiveLink(item, activePath)) {
        element.classList.add('overlay-link--active');
      }

      element.addEventListener('click', () => {
        setMenuState(false);
      });

      linksContainer.appendChild(element);
    });

    overlayInner.appendChild(linksContainer);
    overlay.appendChild(overlayInner);
    doc.body.appendChild(overlay);

    function setMenuState(isOpen) {
      overlay.classList.toggle('open', isOpen);
      doc.body.classList.toggle('menu-open', isOpen);
      overlay.setAttribute('aria-hidden', String(!isOpen));
      openToggle.setAttribute('aria-expanded', String(isOpen));
      openToggle.classList.toggle('active', isOpen);
      closeToggle.classList.toggle('active', isOpen);
    }

    openToggle.addEventListener('click', () => {
      const isOpen = overlay.classList.contains('open');
      setMenuState(!isOpen);
    });

    closeToggle.addEventListener('click', () => setMenuState(false));

    overlay.addEventListener('click', (event) => {
      if (event.target === overlay) {
        setMenuState(false);
      }
    });

    doc.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') {
        setMenuState(false);
      }
    });
  }

  if (doc.readyState === 'loading') {
    doc.addEventListener('DOMContentLoaded', buildMenu);
  } else {
    buildMenu();
  }
})();
