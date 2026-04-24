document.addEventListener('DOMContentLoaded', () => {

    // --- Global Cart Logic ---
    const CART_KEY = 'hearth_cart';

    function getCart() {
        const stored = localStorage.getItem(CART_KEY);
        return stored ? JSON.parse(stored) : [];
    }

    function saveCart(cart) {
        localStorage.setItem(CART_KEY, JSON.stringify(cart));
        updateCartCount();
    }

    function addToCart(product) {
        const cart = getCart();
        cart.push(product);
        saveCart(cart);
        updateCartCount();
    }

    function updateCartCount() {
        // Find badge if we add one later
        const cart = getCart();
        const count = cart.length;
        // console.log("Cart count:", count);
    }

    // Initialize
    updateCartCount();


    // --- Shop Page Specifics ---
    if (window.location.pathname.includes('shop.html')) {
        const modal = document.getElementById('product-modal');
        const modalClose = document.querySelector('.modal-close');
        const quickViewBtns = document.querySelectorAll('.btn-quick-view');
        const addToCartBtns = document.querySelectorAll('.btn-add-cart'); // Grid buttons
        const modalAddToCartBtn = document.getElementById('modal-add-cart'); // Add a button to modal manually if needed, 
        // currently we only have "Order via Whatsapp" there?
        // Let's reuse the WhatsApp button as "Order Now" 
        // but user wants "Cart" section.
        // Actually, the previous implementation had "Order via WhatsApp" directly in modal.
        // But the user requested a cart. So we should change that button to "Add to Cart" or "Buy Now".
        // For checkout flow, we should add to cart then go to checkout.

        // Let's change the Modal Button to "Add to Cart" dynamically or add a second one.
        // For simplicity, let's keep the modal button as "Add to Cart" which redirects to checkout or just adds.
        const modalWhatsappBtn = document.getElementById('modal-whatsapp-btn');
        if (modalWhatsappBtn) {
            modalWhatsappBtn.innerHTML = `<i data-feather="shopping-cart"></i> Add to Cart & Checkout`;
            modalWhatsappBtn.removeAttribute('href'); // We will handle click
            modalWhatsappBtn.removeAttribute('target');
        }

        // Modal Elements
        const modalImg = document.getElementById('modal-img');
        const modalTitle = document.getElementById('modal-title');
        const modalPrice = document.getElementById('modal-price');
        const modalDesc = document.getElementById('modal-desc');
        const modalSpecsContainer = document.getElementById('modal-specs-container'); // Need to create this in HTML first? No, we can inject into modal contents
        // Wait, the HTML structure for modal needs to support specs rendering. 
        // We probably need to replace the innerHTML of the description or add a new container.
        // Let's assume we will insert it after description.

        const qtyInput = document.getElementById('modal-qty');
        const sizeSelect = document.getElementById('modal-size');
        const colorSelect = document.getElementById('modal-color');
        const colorGroup = document.getElementById('modal-color-group');
        const sizeLabel = document.querySelector('label[for="modal-size"]');

        let currentProductData = {};

        function openModal(productElement) {
            const title = productElement.querySelector('.product-title').innerText;
            const price = productElement.querySelector('.product-price') ? productElement.querySelector('.product-price').innerText : productElement.querySelector('.price').innerText;

            const imgElement = productElement.querySelector('img');
            const realImgSrc = imgElement ? imgElement.src : null;

            const desc = productElement.dataset.description || "No description.";
            const category = productElement.dataset.category || "apparel";
            const specsRaw = productElement.dataset.specs || "";

            currentProductData = { title, price, imgSrc: realImgSrc, desc, category };

            modalTitle.innerText = title;
            modalPrice.innerText = price;

            // Render Description and Specs
            let specsHTML = '';
            if (specsRaw) {
                const specsList = specsRaw.split('|');
                const specsItems = specsList.map(spec => {
                    const [key, val] = spec.split(':');
                    return `
                        <div class="spec-item">
                            <span class="spec-label">${key.trim()}</span>
                            <span class="spec-value">${val ? val.trim() : ''}</span>
                        </div>
                    `;
                }).join('');

                specsHTML = `
                    <div class="modal-specs">
                        <span class="specs-title">Product Specifications</span>
                        <div class="specs-grid">
                            ${specsItems}
                        </div>
                    </div>
                `;
            }

            modalDesc.innerHTML = `
                <div class="modal-category">${category}</div>
                <div class="modal-description">${desc}</div>
                ${specsHTML}
            `;

            if (realImgSrc) {
                modalImg.src = realImgSrc;
                modalImg.style.display = 'block';
            } else {
                modalImg.style.display = 'none';
            }

            // Dynamic Options Logic
            if (category === 'book') {
                colorGroup.style.display = 'none';
                sizeLabel.innerText = "Format";
                sizeSelect.innerHTML = `
                    <option value="Hard Copy">Hard Copy (Physical)</option>
                    <option value="E-Pub">E-Pub (Digital)</option>
                `;
            } else if (category === 'accessories') {
                const colorsRaw = productElement.dataset.colors || "";
                if (colorsRaw) {
                    colorGroup.style.display = 'block';
                    const colors = colorsRaw.split(',').map(c => c.trim());
                    colorSelect.innerHTML = colors.map(c => `<option value="${c}">${c}</option>`).join('');
                } else {
                    colorGroup.style.display = 'none';
                }

                sizeLabel.innerText = "Size";
                sizeSelect.innerHTML = `
                    <option value="One Size">One Size</option>
                `;
            } else {
                const colorsRaw = productElement.dataset.colors || "";
                if (colorsRaw) {
                    colorGroup.style.display = 'block';
                    const colors = colorsRaw.split(',').map(c => c.trim());
                    colorSelect.innerHTML = colors.map(c => `<option value="${c}">${c}</option>`).join('');
                } else {
                    colorGroup.style.display = 'none';
                }

                sizeLabel.innerText = "Size";
                sizeSelect.innerHTML = `
                    <option value="S">Small</option>
                    <option value="M" selected>Medium</option>
                    <option value="L">Large</option>
                    <option value="XL">XL</option>
                    <option value="XXL">XXL</option>
                `;
            }

            // Handle Image Swapping on Color Change
            if (colorSelect) {
                colorSelect.onchange = () => {
                    const selectedColor = colorSelect.value.toLowerCase();
                    const colorImg = productElement.dataset[`img${selectedColor.charAt(0).toUpperCase() + selectedColor.slice(1)}`];
                    if (colorImg) {
                        modalImg.src = colorImg;
                    } else if (currentProductData.imgSrc) {
                        modalImg.src = currentProductData.imgSrc;
                    }
                };
            }

            modal.classList.add('active');
        }

        quickViewBtns.forEach(btn => {
            btn.addEventListener('click', (e) => {
                const card = btn.closest('.product-card');
                openModal(card);
            });
        });

        // Close Modal
        if (modalClose) modalClose.addEventListener('click', () => modal.classList.remove('active'));
        window.addEventListener('click', (e) => { if (e.target === modal) modal.classList.remove('active'); });


        // Handle Modal Add to Cart
        const modalAddCartBtn = document.getElementById('modal-add-cart-btn');
        if (modalAddCartBtn) {
            modalAddCartBtn.addEventListener('click', () => {
                const qty = qtyInput.value;
                const size = sizeSelect ? sizeSelect.value : 'M';
                const color = (colorGroup && colorGroup.style.display !== 'none') ? colorSelect.value : '';
                addToCart({ ...currentProductData, qty, size, color });
                modal.classList.remove('active');
            });
        }

        // Handle Modal Instant WhatsApp Order
        if (modalWhatsappBtn) {
            modalWhatsappBtn.addEventListener('click', (e) => {
                e.preventDefault();
                const qty = qtyInput.value;
                const size = sizeSelect ? sizeSelect.value : 'M';
                const color = (colorGroup && colorGroup.style.display !== 'none') ? colorSelect.value : '';

                let msg = `🛍️ *H&H SHOP INSTANT ORDER*\n`;
                msg += `------------------------------\n`;
                msg += `*Item:* ${currentProductData.title}\n`;
                msg += `*Price:* ${currentProductData.price}\n`;
                msg += `*Quantity:* ${qty}\n`;
                if (color) msg += `*Color:* ${color}\n`;
                if (size) msg += `*Size:* ${size}\n`;
                msg += `------------------------------\n`;
                msg += `_Interested in purchasing this item immediately._`;

                const adminPhone = "254114433429";
                window.open(`https://wa.me/${adminPhone}?text=${encodeURIComponent(msg)}`, '_blank');
            });
        }

        // Direct Add to Cart from Grid
        addToCartBtns.forEach(btn => {
            btn.addEventListener('click', (e) => {
                const card = btn.closest('.product-card');
                const title = card.querySelector('.product-title').innerText;
                const price = card.querySelector('.product-price') ? card.querySelector('.product-price').innerText : card.querySelector('.price').innerText;
                const imgEl = card.querySelector('img');
                const imgSrc = imgEl ? imgEl.src : '';

                const colorsRaw = card.dataset.colors || "";
                const defaultColor = colorsRaw ? colorsRaw.split(',')[0].trim() : "";
                const desc = card.dataset.description || "No description available.";
                const category = card.dataset.category || "general";

                // Default size/format logic
                let defaultSize = 'M';
                if (category === 'book') defaultSize = 'Hard Copy';
                if (category === 'accessories') defaultSize = 'One Size';

                addToCart({
                    title,
                    price,
                    qty: 1,
                    size: defaultSize,
                    color: defaultColor,
                    desc,
                    category,
                    imgSrc
                });

                // Visual Feedback
                const original = btn.innerHTML;
                btn.innerHTML = `<i data-feather="check"></i>`;
                feather.replace();
                setTimeout(() => { btn.innerHTML = original; feather.replace(); }, 1500);
            });
        });
    }


    // --- Checkout Page Specifics ---
    if (window.location.pathname.includes('checkout.html')) {
        const cartItemsContainer = document.getElementById('checkout-cart-items');
        const cartTotalEl = document.getElementById('checkout-total');
        const completeOrderBtn = document.getElementById('btn-complete-order');

        // Render Cart
        const cart = getCart();
        cartItemsContainer.innerHTML = '';
        let total = 0;

        if (cart.length === 0) {
            cartItemsContainer.innerHTML = '<p>Your cart is empty.</p>';
        } else {
            cart.forEach((item, index) => {
                // Parse price "KSH 1000" -> 1000
                const priceVal = parseFloat(item.price.replace(/[^0-9.]/g, ''));
                const lineTotal = priceVal * parseInt(item.qty);
                total += lineTotal;

                const row = document.createElement('div');
                row.className = 'cart-item-row';
                row.innerHTML = `
                    <div style="display: flex; gap: 1rem; align-items: center;">
                        ${item.imgSrc ? `<img src="${item.imgSrc}" alt="${item.title}" style="width: 50px; height: 50px; object-fit: cover; border-radius: 4px;">` : ''}
                        <div>
                            <strong>${item.title}</strong><br>
                            <small class="text-muted">
                                ${item.category === 'book' ? 'Format' : 'Size'}: ${item.size} 
                                ${item.color ? '| Color: ' + item.color : ''}
                            </small>
                        </div>
                    </div>
                    <span>KSH ${lineTotal.toLocaleString()}</span>
                `;
                cartItemsContainer.appendChild(row);
            });
        }
        cartTotalEl.innerText = 'KSH ' + total.toLocaleString();


        // Payment Tabs Logic
        const tabs = document.querySelectorAll('.payment-tab');
        const details = document.querySelectorAll('.payment-details');

        tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                // Remove active class from all
                tabs.forEach(t => t.classList.remove('active'));
                details.forEach(d => d.classList.remove('active'));

                // Add to current
                tab.classList.add('active');
                const method = tab.dataset.method; // 'mpesa' or 'bank'
                document.getElementById(`${method}-details`).classList.add('active');
            });
        });


        const stkBtn = document.getElementById('btn-stk-push');
        const stkStatus = document.getElementById('stk-status');
        const stkStatusText = document.getElementById('stk-status-text');
        const BACKEND_URL = 'https://hearth-heal-api.onrender.com/api';

        if (stkBtn) {
            stkBtn.addEventListener('click', async () => {
                const phone = document.getElementById('mpesa-phone').value;
                if (!phone || phone.length < 10) {
                    alert("Please enter a valid M-Pesa phone number.");
                    return;
                }

                stkBtn.disabled = true;
                stkStatus.style.display = 'block';
                stkStatusText.innerText = "Initiating STK push...";

                try {
                    // Convert phone to 254 format if needed
                    let formattedPhone = phone;
                    if (phone.startsWith('07') || phone.startsWith('01')) {
                        formattedPhone = '254' + phone.substring(1);
                    }

                    // Call M-Pesa STK Push endpoint
                    const stkRes = await fetch(`${BACKEND_URL}/payments/stk`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            phone: formattedPhone,
                            amount: total,
                            orderId: 'checkout-' + Date.now()
                        })
                    });

                    const stkData = await stkRes.json();

                    if (!stkRes.ok) {
                        throw new Error(stkData.error || "Failed to send STK push");
                    }

                    stkStatusText.innerText = "✓ STK push sent! Check your phone to enter PIN.";

                    // Enable manual transaction code entry
                    setTimeout(() => {
                        stkBtn.disabled = false;
                        stkBtn.innerText = "Send Payment Prompt";
                        stkStatusText.innerText = "Enter the M-Pesa transaction code below to complete your order.";
                    }, 5000);

                } catch (err) {
                    console.error(err);
                    alert("Error: " + err.message);
                    stkBtn.disabled = false;
                    stkStatus.style.display = 'none';
                }
            });
        }


        // Complete Order Logic
        completeOrderBtn.addEventListener('click', () => {
            const name = document.getElementById('cust-name').value;
            const phone = document.getElementById('cust-phone').value;
            const email = document.getElementById('cust-email').value;

            const city = document.getElementById('cust-city').value;
            const street = document.getElementById('cust-street').value;
            // const notes = document.getElementById('cust-notes').value; // Optional

            const trxCode = document.getElementById('payment-code').value;

            if (!name || !phone || !trxCode || !city || !street) {
                alert("Please fill in your Name, Phone, Delivery Location, and Transaction Code.");
                return;
            }

            // Create Payment/Order on Backend
            // For now, we simulate by sending WhatsApp

            // Build WhatsApp Message
            const isVerified = trxCode.startsWith('VERIFIED-');
            let msg = `🧾 *NEW ORDER - HEARTH & HEAL*\n`;
            msg += `------------------------------\n`;
            msg += `👤 *Customer:* ${name}\n`;
            msg += `📍 *Delivery:* ${city}, ${street}\n`;
            msg += `📞 *Phone:* ${phone}\n`;
            msg += `------------------------------\n`;
            msg += `*ITEMS:*\n`;

            cart.forEach(item => {
                const variation = item.size ? item.size : 'Std';
                msg += `• ${item.qty}x ${item.title} [${item.color ? item.color + ', ' : ''}${variation}] @ ${item.price}\n`;
            });

            msg += `------------------------------\n`;
            msg += `💰 *TOTAL: KSH ${total.toLocaleString()}*\n`;
            msg += `------------------------------\n`;
            msg += `💳 *PAYMENT DETAILS:*\n`;
            msg += `*Code:* ${trxCode}\n`;
            msg += `*Status:* ${isVerified ? '✅ VERIFIED VIA MPESA' : '⏳ AWAITING MANUAL VERIFICATION'}\n`;
            msg += `------------------------------\n`;
            msg += `_Order submitted via Hearth & Heal Online Shop._`;

            const adminPhone = "254114433429";
            const url = `https://wa.me/${adminPhone}?text=${encodeURIComponent(msg)}`;

            localStorage.removeItem(CART_KEY); // Clear cart
            window.open(url, '_blank');
            window.location.href = 'index.html';
        });
    }

    // --- Cart Page Specifics ---
    if (window.location.pathname.includes('cart.html')) {
        renderCartPage();
    }

    function renderCartPage() {
        const cartBody = document.getElementById('cart-body');
        const cartSubtotal = document.getElementById('cart-subtotal');
        const cartTotal = document.getElementById('cart-total');
        const cart = getCart();

        cartBody.innerHTML = '';
        let total = 0;

        if (cart.length === 0) {
            cartBody.innerHTML = `
                <div class="empty-cart">
                    <div class="empty-cart-icon">
                        <i data-feather="shopping-cart" style="width: 60px; height: 60px;"></i>
                    </div>
                    <h3>Your cart is empty</h3>
                    <p>Looks like you haven't added any items yet.</p>
                    <a href="shop.html" class="btn-continue-shopping">
                        <i data-feather="shopping-bag"></i> Start Shopping
                    </a>
                </div>
            `;
            if (cartSubtotal) cartSubtotal.innerText = 'KSH 0';
            if (cartTotal) cartTotal.innerText = 'KSH 0';
            feather.replace();
            return;
        }

        cart.forEach((item, index) => {
            const priceVal = parseFloat(item.price.replace(/[^0-9.]/g, ''));
            const qty = parseInt(item.qty);
            const lineTotal = priceVal * qty;
            total += lineTotal;

            const variationLabel = item.category === 'book' ? 'Format' : 'Size';
            const variationValue = item.size || 'Standard';

            const itemDiv = document.createElement('div');
            itemDiv.className = 'cart-item';
            itemDiv.innerHTML = `
                <div class="product-info">
                    ${item.imgSrc ? `<img src="${item.imgSrc}" alt="${item.title}" class="product-image" onerror="this.style.display='none'">` : '<div class="product-image" style="display:flex;align-items:center;justify-content:center;color:rgba(255,255,255,0.3);"><i data-feather="image"></i></div>'}
                    <div class="product-details">
                        <h4>${item.title}</h4>
                        <div class="product-meta">${item.desc ? item.desc.substring(0, 60) + '...' : 'Hearth & Heal Product'}</div>
                        <div class="product-variant">
                            <span>${variationLabel}: ${variationValue}</span>
                            ${item.color ? `<span>Color: ${item.color}</span>` : ''}
                        </div>
                    </div>
                </div>
                <div class="price">${item.price}</div>
                <div class="quantity-control">
                    <button class="quantity-btn" data-index="${index}" data-action="decrease">−</button>
                    <input type="text" value="${qty}" class="quantity-input" readonly>
                    <button class="quantity-btn" data-index="${index}" data-action="increase">+</button>
                </div>
                <div class="item-total">KSH ${lineTotal.toLocaleString()}</div>
                <button class="btn-remove" data-index="${index}" title="Remove item">
                    <i data-feather="trash-2" style="width: 20px; height: 20px;"></i>
                </button>
            `;
            cartBody.appendChild(itemDiv);
        });

        if (cartSubtotal) cartSubtotal.innerText = 'KSH ' + total.toLocaleString();
        if (cartTotal) cartTotal.innerText = 'KSH ' + total.toLocaleString();

        // Event Listeners for Cart Actions
        document.querySelectorAll('.btn-remove').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const index = e.currentTarget.dataset.index;
                cart.splice(index, 1);
                saveCart(cart);
                renderCartPage();
            });
        });

        // Quantity controls
        document.querySelectorAll('.quantity-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const index = e.currentTarget.dataset.index;
                const action = e.currentTarget.dataset.action;
                const currentQty = parseInt(cart[index].qty);
                
                if (action === 'increase' && currentQty < 20) {
                    cart[index].qty = currentQty + 1;
                } else if (action === 'decrease' && currentQty > 1) {
                    cart[index].qty = currentQty - 1;
                }
                
                saveCart(cart);
                renderCartPage();
            });
        });

        // Direct WhatsApp Order from Cart
        const cartWhatsappBtn = document.getElementById('btn-cart-whatsapp');
        if (cartWhatsappBtn) {
            cartWhatsappBtn.addEventListener('click', (e) => {
                e.preventDefault();
                const cartItems = getCart();
                if (cartItems.length === 0) {
                    alert("Your cart is empty.");
                    return;
                }

                let total = 0;
                let msg = `🛍️ *H&H CART ORDER - WHATSAPP*\n`;
                msg += `------------------------------\n`;
                cartItems.forEach(item => {
                    const priceVal = parseFloat(item.price.replace(/[^0-9.]/g, ''));
                    const lineTotal = priceVal * parseInt(item.qty);
                    total += lineTotal;
                    msg += `• ${item.qty}x ${item.title} [${item.color ? item.color + ', ' : ''}${item.size || 'Std'}] @ ${item.price}\n`;
                });
                msg += `------------------------------\n`;
                msg += `💰 *TOTAL: KSH ${total.toLocaleString()}*\n`;
                msg += `------------------------------\n`;
                msg += `_Please confirm my order and share payment instructions._`;

                const adminPhone = "254114433429";
                window.open(`https://wa.me/${adminPhone}?text=${encodeURIComponent(msg)}`, '_blank');
            });
        }

        feather.replace();
    }

});
