/**
 * Olaf - Wellness Companion Chatbot
 * Hearth & Heal Organization
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
    greetings: ["Hi! I'm Olaf and I like warm hugs! 🤗", "Hello there! Isn't it a lovely day for starting over? ✨", "Look at me! I'm a talking snowman! ☃️"],
    personality: ["warm hugs", "summer", "melting", "happiness", "joy", "friends", "reindeer", "carrot"],
    context: {
        mission: "At Hearth & Heal, we believe 'We don’t chase flawless outcomes – We pursue wholeness, grace, and the courage to begin again.' 💚",
        vision: "Our vision is to heal the world and make it habitable for every individual. That's a lot of hugs! 🌍",
        leadership: "We're lead by our Founder, <b>Mr. John Haggee Ouma</b>. He has a heart even warmer than a bonfire! 🔥",
        services: ["Spiritual Care", "Recovery Room", "Creative Healing", "Literature & Authorship"],
        whatsapp: "https://wa.me/254114433429"
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
                    say("How can I help you on your journey to wholeness today? I can tell you about our mission, services, or just give you a virtual hug! 🤗", 'ai');
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

    function processInput() {
        const text = chatInput.value.trim();
        if (!text) return;

        say(text, 'user');
        chatInput.value = '';

        setTimeout(() => {
            const response = getOlafThinking(text);
            say(response, 'ai');
        }, 800);
    }

    sendBtn.onclick = processInput;
    chatInput.onkeypress = (e) => { if (e.key === 'Enter') processInput(); };

    function getOlafThinking(input) {
        const q = input.toLowerCase();

        if (q.includes('hi') || q.includes('hello')) return "Hi there! I'm Olaf! ☃️ Did you bring a warm hug?";
        if (q.includes('mission') || q.includes('why exist')) return olafBrain.context.mission;
        if (q.includes('vision') || q.includes('goal')) return `My goal is to help everyone find wholeness! 💚 "${olafBrain.context.vision}"`;
        if (q.includes('founder') || q.includes('ceo') || q.includes('john')) return olafBrain.context.leadership;
        if (q.includes('service') || q.includes('program') || q.includes('help')) return "We offer Spiritual Care, Creative Healing, and a safe Recovery Room! You can see them all on our <a href='services.html' style='color:#00C853; font-weight:bold;'>Services</a> page! ✨";
        if (q.includes('contact') || q.includes('whatsapp') || q.includes('message')) return `I can't wait to talk to you! You can message us on <a href='${olafBrain.context.whatsapp}' target='_blank' style='color:#00C853; font-weight:bold;'>WhatsApp</a> or email hello@hearthandheal.org! 📱`;
        if (q.includes('hug')) return "I LOVE warm hugs! 🤗 *Squeeeeeeak* There you go!";
        if (q.includes('summer')) return "I LOVE summer! ☀️ Bees'll buzz, kids'll blow dandelion fuzz... and I'll be doing whatever snow does in summer! 🏖️";
        if (q.includes('sad') || q.includes('hurt') || q.includes('pain')) return "Oh, friend... I'm so sorry you're feeling this way. ❄️ Just remember, some people are worth melting for, and YOU are worth everything. Please check our <a href='services.html' style='color:#00C853; font-weight:bold;'>Recovery Room</a>, it's a safe place to heal. 💙";
        if (q.includes('thank')) return "You're so welcome! My carrot nose is twitching with happiness! 🥕✨";

        return "Oh flurry! ❄️ I'm not sure I understand, but I'm listening! Ask me about our mission, services, or if I like warm hugs!";
    }
});
