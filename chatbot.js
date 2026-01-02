/**
 * Olaf - Wellness Companion Chatbot
 * Hearth & Heal Organization
 * Expanded Knowledge Base & Intelligence
 */

const chatbotHTML = `
<div id="olaf-container">
    <div id="olaf-widget">
        <div class="olaf-chat-body">
            <div class="olaf-header">
                <div class="olaf-header-info">
                    <h3>⛄ Olaf</h3>
                    <p>Wellness Companion</p>
                </div>
                <button id="close-chat" aria-label="Close Chat">&times;</button>
            </div>
            <div id="chat-log"></div>
            <div class="chat-input-area">
                <input id="chat-input" type="text" placeholder="I like warm hugs! Say hi..." />
                <button id="send-btn" aria-label="Send Message"><i data-feather="send"></i></button>
            </div>
        </div>
    </div>
    <div id="olaf-trigger" title="Chat with Olaf">
        <img src="assets/olaf_chatbot.jpg" alt="Olaf Character">
        <div class="olaf-status"></div>
    </div>
</div>
`;

const chatbotStyles = `
<style>
  #olaf-container {
    position: fixed;
    bottom: 30px;
    right: 30px;
    z-index: 10000;
    font-family: 'Outfit', sans-serif;
  }

  /* Trigger Button */
  #olaf-trigger {
    width: 85px;
    height: 85px;
    background: white;
    border-radius: 50%;
    box-shadow: 0 12px 30px rgba(0,0,0,0.18);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
    border: 3px solid #00E676;
    position: relative;
    padding: 0;
    overflow: visible;
  }

  #olaf-trigger img {
    width: 100%;
    height: 100%;
    border-radius: 50%;
    object-fit: cover;
    transition: transform 0.4s ease;
  }

  #olaf-trigger:hover {
    transform: scale(1.1) rotate(5deg);
    box-shadow: 0 15px 40px rgba(0, 230, 118, 0.25);
  }

  .olaf-status {
      position: absolute;
      bottom: 5px;
      right: 5px;
      width: 18px;
      height: 18px;
      background: #00E676;
      border: 3px solid white;
      border-radius: 50%;
      box-shadow: 0 2px 5px rgba(0,0,0,0.2);
  }

  /* Chat Widget */
  #olaf-widget {
    display: none;
    width: 380px;
    background: white;
    border-radius: 20px;
    box-shadow: 0 20px 60px rgba(0,0,0,0.25);
    overflow: hidden;
    flex-direction: column;
    margin-bottom: 25px;
    border: 1px solid rgba(0, 230, 118, 0.1);
    transform-origin: bottom right;
  }

  #olaf-widget.active {
    display: flex;
    animation: olafPop 0.5s cubic-bezier(0.22, 1, 0.36, 1);
  }

  @keyframes olafPop {
      from { opacity: 0; transform: scale(0.8) translateY(40px); }
      to { opacity: 1; transform: scale(1) translateY(0); }
  }

  .olaf-header {
    background: linear-gradient(135deg, #00C853, #00E676);
    color: white;
    padding: 25px 20px;
    position: relative;
    display: flex;
    align-items: center;
    border-bottom: 4px solid rgba(255,255,255,0.2);
  }

  .olaf-header-info h3 { 
      margin: 0; 
      font-size: 1.4rem; 
      font-weight: 700;
      letter-spacing: 0.5px;
  }
  .olaf-header-info p { 
      margin: 2px 0 0; 
      font-size: 0.85rem; 
      opacity: 0.95;
      font-weight: 500;
  }

  #close-chat {
    background: rgba(0,0,0,0.1);
    border: none;
    color: white;
    width: 32px;
    height: 32px;
    border-radius: 50%;
    font-size: 20px;
    cursor: pointer;
    margin-left: auto;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: background 0.3s;
  }

  #close-chat:hover { background: rgba(0,0,0,0.2); }

  #chat-log {
    height: 400px;
    overflow-y: auto;
    padding: 25px;
    display: flex;
    flex-direction: column;
    gap: 15px;
    background: #fdfdfd;
  }

  .chat-msg {
    max-width: 80%;
    padding: 14px 18px;
    border-radius: 20px;
    font-size: 0.95rem;
    line-height: 1.6;
    position: relative;
    word-wrap: break-word;
    box-shadow: 0 2px 8px rgba(0,0,0,0.03);
  }

  .msg-ai {
    align-self: flex-start;
    background: white;
    color: #444;
    border-bottom-left-radius: 5px;
    border: 1px solid #f0f0f0;
  }

  .msg-user {
    align-self: flex-end;
    background: #00C853;
    color: white;
    border-bottom-right-radius: 5px;
    font-weight: 500;
  }

  .typing-indicator span {
      display: inline-block;
      width: 5px;
      height: 5px;
      background: #aaa;
      border-radius: 50%;
      margin: 0 1px;
      animation: typing 1.4s infinite both;
  }
  .typing-indicator span:nth-child(2) { animation-delay: 0.2s; }
  .typing-indicator span:nth-child(3) { animation-delay: 0.4s; }

  @keyframes typing {
      0%, 80%, 100% { opacity: 0; transform: translateY(0); }
      40% { opacity: 1; transform: translateY(-5px); }
  }

  .chat-input-area {
    padding: 20px;
    display: flex;
    gap: 12px;
    border-top: 1px solid #f0f0f0;
    background: white;
  }

  #chat-input {
    flex: 1;
    border: 1px solid #eee;
    padding: 12px 20px;
    border-radius: 30px;
    outline: none;
    font-family: inherit;
    font-size: 0.95rem;
    background: #f9f9f9;
    transition: all 0.3s;
  }

  #chat-input:focus {
      background: white;
      border-color: #00E676;
      box-shadow: 0 0 0 3px rgba(0, 230, 118, 0.1);
  }

  #send-btn {
    background: #00C853;
    color: white;
    border: none;
    width: 48px;
    height: 48px;
    border-radius: 50%;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: all 0.3s;
    flex-shrink: 0;
  }

  #send-btn:hover {
      background: #00E676;
      transform: scale(1.05);
      box-shadow: 0 5px 15px rgba(0, 200, 83, 0.3);
  }

  #send-btn svg { width: 22px; height: 22px; }

  /* Mobile Tweaks */
  @media (max-width: 480px) {
    #olaf-widget { width: 90vw; right: -10vw; position: relative; }
    #olaf-container { bottom: 20px; right: 20px; }
  }
</style>
`;

// --- OLAF KNOWLEDGE ---
const olafBrain = {
  greetings: [
    "Hi! I'm Olaf and I like warm hugs! 🤗",
    "Hello there! Isn't it a lovely day for starting over? ✨",
    "Look at me! I'm a talking snowman! ☃️",
    "Good morning! Or evening! I don't have a watch, but I have a carrot! 🥕"
  ],
  personality: ["warm hugs", "summer", "melting", "happiness", "joy", "friends", "reindeer", "carrot", "love"],
  context: {
    mission: "Hearth & Heal exists to provide a safe, inclusive, and restorative environment for individuals navigating personal adversity and social marginalization. 💚",
    vision: "Our vision is to heal the world and make it habitable for every individual. That's a lot of hugs! 🌍",
    quote: "\"We don’t chase flawless outcomes – We pursue wholeness, grace, and the courage to begin again.\"",
    leadership: "We're lead by our Founder & CEO, <b>Mr. John Haggee Ouma</b>. He's also an author! 🌟",
    values: [
      "Compassion over Judgement",
      "Truth Rooted in God’s Word",
      "Dignity for Every Individual",
      "Healing Through Community",
      "Empowerment Through Self-Help"
    ],
    services: {
      "spiritual care": "Guided reflections, prayer circles, and spiritual companionship to nourish your soul. ⚓",
      "creative healing": "I LOVE this! Expressive arts, bonfires, dance, and music therapy. It's so much fun! 🎨🔥",
      "recovery room": "A safe place for facilitated conversations and unpacking life's heavy ordeals. 🛋️",
      "literature": "We have books and workshops! Writing can be so healing for the heart. 📚",
      "resource navigation": "We help with basic needs like food and shelter, plus legal aid navigation. 🧭",
      "sensitization": "Awareness workshops and civic education to help societies function better! 📢"
    },
    shop: {
      book: "Our CEO wrote a wonderful book: <b>'I Chose To Let You Down'</b> (KSH 1,000). It's about the route from heartbreak to healing. 📖",
      apparel: "We have branded Hoodies (KSH 2,500), Sweatshirts (KSH 2,000), T-Shirts (KSH 750), and Polo Shirts (KSH 1,000)! 👕",
      accessories: "We have Headbands (KSH 500), Scarves (KSH 600), and Baseball Caps (KSH 500)! 🧢"
    },
    donation: {
      impact: "Every bit helps! KSH 1,000 provides materials, KSH 5,000 supports a group session, and KSH 25,000 rents a safe space for an entire month! 💖",
      methods: "You can use PayPal, M-Pesa (Paybill: 123456, Acc: HEARTH), or Bank Transfer! Check the <a href='donate.html'>Donate</a> page for details."
    },
    contact: {
      email: "hello@hearthandheal.org",
      whatsapp: "254114433429",
      socials: "Find us on TikTok (@hearth.heal.org), Instagram, YouTube, and Facebook! 📱"
    }
  }
};

document.addEventListener('DOMContentLoaded', () => {
  // 1. Setup
  document.body.insertAdjacentHTML('beforeend', chatbotHTML);
  document.head.insertAdjacentHTML('beforeend', chatbotStyles);
  if (window.feather) feather.replace();

  const trigger = document.getElementById('olaf-trigger');
  const widget = document.getElementById('olaf-widget');
  const closeBtn = document.getElementById('close-chat');
  const chatLog = document.getElementById('chat-log');
  const chatInput = document.getElementById('chat-input');
  const sendBtn = document.getElementById('send-btn');

  // 2. Logic
  trigger.onclick = () => {
    widget.classList.add('active');
    trigger.style.display = 'none';

    // Introductory message
    if (chatLog.children.length === 0) {
      setTimeout(() => {
        say(olafBrain.greetings[Math.floor(Math.random() * olafBrain.greetings.length)], 'ai');
        setTimeout(() => {
          say("I'm here to help you learn about Hearth & Heal! Ask me about our <b>mission</b>, <b>services</b>, <b>shop</b>, or how to <b>donate</b>. Or just ask for a <b>hug</b>! 🤗", 'ai');
        }, 1000);
      }, 500);
    }
  };

  closeBtn.onclick = () => {
    widget.classList.remove('active');
    trigger.style.display = 'flex';
  };

  function say(text, sender) {
    const msg = document.createElement('div');
    msg.className = `chat-msg msg-${sender}`;
    msg.innerHTML = text;
    chatLog.appendChild(msg);
    chatLog.scrollTop = chatLog.scrollHeight;
  }

  function showTyping() {
    const typing = document.createElement('div');
    typing.className = 'chat-msg msg-ai typing-indicator';
    typing.id = 'olaf-typing';
    typing.innerHTML = '<span>.</span><span>.</span><span>.</span>';
    chatLog.appendChild(typing);
    chatLog.scrollTop = chatLog.scrollHeight;
    return typing;
  }

  function processInput() {
    const text = chatInput.value.trim();
    if (!text) return;

    say(text, 'user');
    chatInput.value = '';

    const typingIndicator = showTyping();

    setTimeout(() => {
      typingIndicator.remove();
      const response = getOlafThinking(text);
      say(response, 'ai');
    }, 1000);
  }

  sendBtn.onclick = processInput;
  chatInput.onkeypress = (e) => { if (e.key === 'Enter') processInput(); };

  function getOlafThinking(input) {
    const q = input.toLowerCase();

    // Greetings
    if (q.match(/\b(hi|hello|hey|jambo)\b/)) return "Hi there! I'm Olaf! ☃️ Did you bring a warm hug?";

    // Mission & Vision
    if (q.includes('mission')) return `My mission is your healing! 💚 "${olafBrain.context.mission}"`;
    if (q.includes('vision')) return `We're healing the world, one hug at a time! 🌍 "${olafBrain.context.vision}"`;
    if (q.includes('quote') || q.includes('flawless')) return `I love this reminder: <i>${olafBrain.context.quote}</i> ✨`;
    if (q.includes('value') || q.includes('stand for')) return `We stand for: ${olafBrain.context.values.join(', ')}. No judgement here! 🤝`;

    // Services
    if (q.includes('service') || q.includes('program') || q.includes('what do you do')) {
      return "We offer so many ways to heal! Spiritual Care, Creative Healing (my favorite!), a Recovery Room, and Resource Navigation! Check the <a href='services.html' style='color:#00C853; font-weight:bold;'>Services</a> page for the full list! ✨";
    }
    if (q.includes('spiritual')) return olafBrain.context.services["spiritual care"];
    if (q.match(/\b(creative|art|dance|music|bonfire)\b/)) return olafBrain.context.services["creative healing"];
    if (q.includes('recovery')) return olafBrain.context.services["recovery room"];
    if (q.match(/\b(book|write|author|literature)\b/)) return olafBrain.context.services["literature"];
    if (q.includes('resource') || q.includes('needs') || q.includes('legal')) return olafBrain.context.services["resource navigation"];

    // Leadership
    if (q.includes('founder') || q.includes('ceo') || q.includes('john') || q.includes('who runs')) return olafBrain.context.leadership;

    // Shop
    if (q.includes('shop') || q.includes('buy') || q.includes('merch') || q.includes('product')) {
      return `We have Branded Hoodies, Sweatshirts, and more! Plus our CEO's book. 🛍️ Visit our <a href='shop.html' style='color:#00C853; font-weight:bold;'>Shop</a> to support our mission!`;
    }
    if (q.includes('hoodie') || q.includes('shirt') || q.includes('apparel')) return olafBrain.context.shop.apparel;
    if (q.includes('scarf') || q.includes('cap')) return olafBrain.context.shop.accessories;

    // Donations
    if (q.includes('donate') || q.includes('give') || q.includes('money') || q.includes('support')) {
      return `You're so kind! 💖 ${olafBrain.context.donation.methods} ${olafBrain.context.donation.impact}`;
    }
    if (q.includes('mpesa')) return "For M-Pesa, use <b>Paybill 123456</b> and <b>Account HEARTH</b>! Thank you! 📱";

    // Contact
    if (q.includes('contact') || q.includes('whatsapp') || q.includes('message') || q.includes('email') || q.includes('social')) {
      return `Find us on social media: ${olafBrain.context.contact.socials} Or email <b>${olafBrain.context.contact.email}</b> or WhatsApp <b>${olafBrain.context.contact.whatsapp}</b>! 📱`;
    }

    // Personality / Fun
    if (q.includes('hug')) return "I LOVE warm hugs! 🤗 *Squeeeeeeak* There you go! Can you feel the warmth?";
    if (q.includes('summer')) return "I LOVE summer! ☀️ Bees'll buzz, kids'll blow dandelion fuzz... and I'll be doing whatever snow does in summer! 🏖️";
    if (q.includes('reindeer') || q.includes('sven')) return "Sven is my best friend! 🦌 We go on so many adventures together!";
    if (q.match(/\b(carrot|nose)\b/)) return "My nose is a carrot! 🥕 Is it straight? Sometimes it gets a bit wiggly!";

    // Emotional Support
    if (q.match(/\b(sad|hurt|pain|lonely|depressed|cry)\b/)) {
      return "Oh, friend... I wish I could give you a real hug right now. ❄️ Just remember, some people are worth melting for, and YOU are worth everything. Hearth & Heal is here for you. Check out our <a href='services.html' style='color:#00C853; font-weight:bold;'>Recovery Room</a> for a safe space to talk. 💙";
    }

    if (q.includes('thank')) return "You're so welcome! My heart is melting with gratitude! 🥕✨";

    return "Oh flurry! ❄️ I'm not sure I understand that, but I'm still learning! Ask me about our mission, services, or if I like warm hugs!";
  }
});
