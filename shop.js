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
        const trxInput = document.getElementById('payment-code');
        const BACKEND_URL = 'https://hearth-heal-org.onrender.com';

        if (stkBtn) {
            stkBtn.addEventListener('click', async () => {
                const phone = document.getElementById('mpesa-phone').value;
                if (!phone || phone.length < 10) {
                    alert("Please enter a valid M-Pesa phone number.");
                    return;
                }

                stkBtn.disabled = true;
                stkStatus.style.display = 'block';
                stkStatusText.innerText = "Initiating prompt...";

                try {
                    // 1. Create Invoice
                    const invRes = await fetch(`${BACKEND_URL}/invoices`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            customerId: phone,
                            amount: total,
                            currency: 'KES',
                            description: 'Hearth & Heal Merchandise'
                        })
                    });
                    const invoice = await invRes.json();

                    if (!invRes.ok) throw new Error(invoice.error || "Failed to create invoice");

                    // 2. Trigger Payment (STK Push)
                    const payRes = await fetch(`${BACKEND_URL}/payments`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            reference_number: invoice.reference_number,
                            channel: 'mpesa'
                        })
                    });
                    const payment = await payRes.json();

                    stkStatusText.innerText = "Prompt sent! Awaiting payment...";

                    // 3. Poll for Status
                    const pollInterval = setInterval(async () => {
                        try {
                            const statusRes = await fetch(`${BACKEND_URL}/invoices/${invoice.reference_number}`);
                            const statusData = await statusRes.json();

                            if (statusData.status === 'PAID') {
                                clearInterval(pollInterval);
                                stkStatusText.innerHTML = "✅ <span style='color:green; font-weight:bold;'>Payment Verified Automatically!</span>";
                                trxInput.value = "VERIFIED-" + invoice.reference_number;
                                trxInput.style.backgroundColor = '#d4edda';
                                stkBtn.innerText = "Paid & Verified";
                            } else if (statusData.status === 'FAILED') {
                                clearInterval(pollInterval);
                                stkStatusText.innerHTML = "❌ <span style='color:red; font-weight:bold;'>Payment Failed or Cancelled.</span>";
                                stkBtn.disabled = false;
                                stkBtn.innerText = "Retry Payment";
                            }
                        } catch (e) {
                            console.error("Polling error:", e);
                        }
                    }, 3000);

                    // Timeout polling after 2 minutes
                    setTimeout(() => clearInterval(pollInterval), 120000);

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
        const cartTotal = document.getElementById('cart-total');
        const cart = getCart();

        cartBody.innerHTML = '';
        let total = 0;

        if (cart.length === 0) {
            cartBody.innerHTML = '<tr><td colspan="5">Your cart is empty.</td></tr>';
            cartTotal.innerText = 'Grand Total: KSH 0';
            return;
        }

        cart.forEach((item, index) => {
            const priceVal = parseFloat(item.price.replace(/[^0-9.]/g, ''));
            const qty = parseInt(item.qty);
            const lineTotal = priceVal * qty;
            total += lineTotal;

            const variationLabel = item.category === 'book' ? 'Format' : 'Size';
            const variationValue = item.size || 'Standard';

            const row = document.createElement('tr');
            row.innerHTML = `
                <td style="display: flex; gap: 1rem; align-items: start;">
                    ${item.imgSrc ? `<img src="${item.imgSrc}" alt="${item.title}" style="width: 80px; height: 80px; object-fit: cover; border-radius: 8px;">` : ''}
                    <div>
                        <div style="font-weight:700; font-size: 1.1rem; margin-bottom: 0.25rem;">${item.title}</div>
                        <div style="font-size:0.9rem; color:#666; margin-bottom: 0.5rem; line-height: 1.4; max-width: 300px;">
                            ${item.desc || 'No description available'}
                        </div>
                        <div style="font-size:0.8rem; color:#888; background: rgba(0,0,0,0.05); display: inline-block; padding: 2px 8px; border-radius: 4px;">
                            <span style="font-weight: 600; color: #333;">${variationLabel}:</span> ${variationValue}
                            ${item.color ? `<span style="margin-left:8px; border-left:1px solid #ccc; padding-left:8px;"><span style="font-weight: 600; color: #333;">Color:</span> ${item.color}</span>` : ''}
                        </div>
                    </div>
                </td>
                <td style="vertical-align: top; padding-top: 1rem;">${item.price}</td>
                <td style="vertical-align: top; padding-top: 1rem;">
                    <input type="number" value="${qty}" min="1" max="20" data-index="${index}" class="cart-qty-input" style="width: 60px; padding: 5px;">
                </td>
                <td style="vertical-align: top; padding-top: 1rem; font-weight: 600;">KSH ${lineTotal.toLocaleString()}</td>
                <td style="vertical-align: top; padding-top: 1rem;"><button class="btn-remove" data-index="${index}" style="color: red; background: none; border: none; cursor: pointer; text-decoration: underline;">Remove</button></td>
            `;
            cartBody.appendChild(row);
        });

        cartTotal.innerText = 'Grand Total: KSH ' + total.toLocaleString();

        // Event Listeners for Cart Actions
        document.querySelectorAll('.btn-remove').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const index = e.target.dataset.index;
                cart.splice(index, 1);
                saveCart(cart);
                renderCartPage();
            });
        });

        document.querySelectorAll('.cart-qty-input').forEach(input => {
            input.addEventListener('change', (e) => {
                const index = e.target.dataset.index;
                const newQty = parseInt(e.target.value);
                if (newQty > 0) {
                    cart[index].qty = newQty;
                    saveCart(cart);
                    renderCartPage();
                }
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
                    const priceVal = parseFloat(item.price.replace('KSH ', ''));
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
    }

});
