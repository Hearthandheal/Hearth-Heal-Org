// Snowy - Simple Widget Chatbot

const chatbotHTML = `
<div id="snowy">
    <svg id="snowy-svg" width="120" height="200" viewBox="0 0 120 200">
        <!-- Bottom circle -->
        <circle cx="60" cy="150" r="40" fill="#fff" stroke="#000" stroke-width="2"/>
        <!-- Middle circle -->
        <circle cx="60" cy="90" r="30" fill="#fff" stroke="#000" stroke-width="2"/>
        <!-- Head circle -->
        <circle cx="60" cy="40" r="20" fill="#fff" stroke="#000" stroke-width="2"/>
        <!-- Eyes -->
        <circle cx="52" cy="35" r="3" fill="#000"/>
        <circle cx="68" cy="35" r="3" fill="#000"/>
        <!-- Nose -->
        <polygon points="60,40 80,45 60,50" fill="orange"/>
        <!-- Arms -->
        <line id="left-arm" x1="30" y1="90" x2="10" y2="60" stroke="#654321" stroke-width="4"/>
        <line id="right-arm" x1="90" y1="90" x2="110" y2="60" stroke="#654321" stroke-width="4"/>
    </svg>
    <h3>⛄ Snowy the Chatbot</h3>
    <div id="chat-log"></div>
    <input id="chat-input" type="text" placeholder="Say hi..." />
</div>
`;

const chatbotStyles = `
<style>
  #snowy {
    position: fixed;
    bottom: 20px;
    right: 20px;
    width: 300px;
    border: 2px solid #88c;
    border-radius: 15px;
    background: #f0f8ff; /* AliceBlue */
    padding: 10px;
    box-shadow: 0 0 10px rgba(0,0,0,0.2);
    font-family: 'Outfit', sans-serif;
    z-index: 9999;
    text-align: center;
    animation: bounce 3s infinite;
    cursor: pointer; /* Interaction hint */
    transition: right 0.5s ease, left 0.5s ease; /* Smooth movement */
  }

  @keyframes bounce {
    0%, 100% { transform: translateY(0); }
    50% { transform: translateY(-10px); }
  }

  #snowy-svg {
      height: 80px;
      width: auto;
      margin-bottom: -10px;
      filter: drop-shadow(0 2px 4px rgba(0,0,0,0.1));
  }

  /* User Defined Animations */
  #left-arm {
    transform-origin: 30px 90px;
    animation: wave 2s infinite;
  }

  @keyframes wave {
    0%, 100% { transform: rotate(0deg); }
    50% { transform: rotate(-20deg); }
  }

  .fast-wave {
      animation-duration: 0.2s !important;
  }

  #chat-log { 
    max-height: 200px; 
    overflow-y: auto; 
    margin-bottom: 10px;
    display: flex;
    flex-direction: column;
    gap: 8px;
    text-align: left; /* Reset text align for messages */
    cursor: auto;
  }
  
  #chat-input { 
    width: 90%; 
    padding: 8px; 
    margin-top: 5px; 
    border-radius: 5px;
    border: 1px solid #ccc;
    cursor: text;
  }

  /* Message Styles */
  .msg-user { color: #333; background: #e0e0e0; padding: 5px 10px; border-radius: 10px; align-self: flex-end; max-width: 90%; font-size: 0.9rem; }
  .msg-ai { color: #0044cc; background: white; padding: 5px 10px; border-radius: 10px; border: 1px solid #cce5ff; align-self: flex-start; max-width: 90%; font-size: 0.9rem; }

  #snowy h3 {
      margin-top: 5px;
      color: #1565C0;
      border-bottom: 1px solid #ddd;
      padding-bottom: 5px;
  }
</style>
`;

// --- KNOWLEDGE BASE ---
const knowledgeBase = {
    mission: "Hearth & Heal exists to provide a safe, inclusive, and restorative environment for individuals navigating personal adversity, relational dysfunction and social marginalization.",
    vision: "Our vision is to heal the world and make it habitable for every individual.",
    founder: "Our wonderful leadership is guided by **Mr. John Haggee Ouma**, our CEO and Founder. He has such a big heart!",
    values: [
        "**Compassion over Judgement** - We meet every story with tenderness.",
        "**Truth Rooted in God’s Word** - Finding clarity and divine purpose.",
        "**Dignity for Every Individual** - Everyone is worth it!",
        "**Healing Through Community** - We are better together.",
        "**Empowerment Through Self-Help** - Helping you walk your own journey."
    ],
    contact: {
        address: "123 Wellness Way, Serenity City",
        email: "hello@hearthandheal.org",
        phone: "(555) 123-4567"
    },
    services: [
        { name: "Spiritual Care", desc: "Guided reflections, prayer circles, and spiritual companionship." },
        { name: "Literature & Authorship", desc: "Our published books and writing workshops." },
        { name: "Creative Healing", desc: "Expressive arts, bonfires, and dance therapy! So fun!" },
        { name: "Recovery Room", desc: "Safe spaces for confessions and unpacking ordeals." },
        { name: "Resource Navigation", desc: "Help with basic needs and legal aid." },
        { name: "Dysfunctionality Sensitization", desc: "Awareness workshops and civic education." }
    ]
};

document.addEventListener('DOMContentLoaded', () => {
    // 1. Remove old container if it exists (cleanup)
    const oldContainer = document.getElementById('ai-chatbot-container');
    if (oldContainer) oldContainer.remove();
    const oldWidget = document.getElementById('snowy-chatbot');
    if (oldWidget) oldWidget.remove();
    const reallyOldWidget = document.getElementById('snowy');
    if (reallyOldWidget) reallyOldWidget.remove();


    // 2. Inject New Widget
    document.body.insertAdjacentHTML('beforeend', chatbotHTML);
    document.head.insertAdjacentHTML('beforeend', chatbotStyles);

    // 3. Logic
    const snowy = document.getElementById("snowy"); // Changed ID to snowy
    const log = document.getElementById("chat-log");
    const input = document.getElementById("chat-input");

    // Click to Toggle Position Logic
    snowy.addEventListener("click", (e) => {
        // Prevent moving when clicking input or selecting text in log
        if (e.target === input || e.target.closest('#chat-log')) return;

        snowy.style.right = snowy.style.right === "20px" ? "auto" : "20px";
        snowy.style.left = snowy.style.left === "20px" ? "auto" : "20px";
    });

    // Handle Input
    input.addEventListener("keypress", (e) => {
        if (e.key === "Enter") {
            const userText = input.value.trim();
            if (!userText) return;

            // User Message
            log.innerHTML += `<div class="msg-user"><b>You:</b> ${userText}</div>`;
            input.value = "";

            // Fast Wave Reaction
            const leftArm = document.getElementById('left-arm');
            if (leftArm) leftArm.classList.add('fast-wave');

            // AI Response (Using our Logic)
            setTimeout(() => {
                const response = getAiResponse(userText);
                log.innerHTML += `<div class="msg-ai"><b>Snowy:</b> ${response}</div>`;
                log.scrollTop = log.scrollHeight; // Auto scroll

                // Stop Fast Wave
                if (leftArm) leftArm.classList.remove('fast-wave');
            }, 500); // 0.5s reaction time

            log.scrollTop = log.scrollHeight;
        }
    });
});

// --- REUSED INTELLIGENCE LOGIC ---
function getAiResponse(input) {
    const lowerInput = input.toLowerCase();

    // 1. Mission & Vision
    if (lowerInput.includes('mission')) return `Our Mission:<br>"${knowledgeBase.mission}"<br><br>It warms my heart! 🔥`;
    if (lowerInput.includes('vision')) return `Our Vision:<br>"${knowledgeBase.vision}"<br><br>Clear as a crisp winter morning! ☀️`;

    // 2. Values
    if (lowerInput.includes('values') || lowerInput.includes('stand for') || lowerInput.includes('belief')) {
        let valuesList = knowledgeBase.values.map(v => `• ${v}`).join('<br>');
        return `We believe in kindness like falling snow! ❄️ Here they are:<br><br>${valuesList}`;
    }

    // 3. Team / Founder
    if (lowerInput.includes('founder') || lowerInput.includes('ceo') || lowerInput.includes('john') || lowerInput.includes('who runs')) {
        return `That's **Mr. John Haggee Ouma**! He's the coolest (pun intended)! 😎`;
    }

    // 4. Services
    const matchedService = knowledgeBase.services.find(s => lowerInput.includes(s.name.toLowerCase()));
    if (matchedService) {
        return `Ah, **${matchedService.name}**! ✨<br>${matchedService.desc}<br><br>Check the <a href='services.html' style='color:#1565C0; font-weight:bold;'>Services</a> page!`;
    }

    if (lowerInput.includes('service') || lowerInput.includes('program')) {
        return "We have lots of ways to help! Spiritual Care, Creative Healing... it's a winter wonderland of support! 🏔️ Which one interests you?";
    }

    // 5. Emotional Support
    if (lowerInput.includes('sad') || lowerInput.includes('depressed') || lowerInput.includes('lonely') || lowerInput.includes('help') || lowerInput.includes('hurt')) {
        return "Oh, don't feel blue like ice! 🧊 You matter so much! <br><br> Maybe visit our <a href='services.html' style='color:#1565C0; font-weight:bold;'>Recovery Room</a>? We're here to warm you up! 💙";
    }

    // 6. Contact
    if (lowerInput.includes('contact') || lowerInput.includes('address') || lowerInput.includes('email')) {
        return `Write to us at: <b>${knowledgeBase.contact.email}</b>.<br>Or visit: <b>${knowledgeBase.contact.address}</b>.`;
    }

    // 7. General Greetings
    if (lowerInput.includes('hi') || lowerInput.includes('hello')) {
        return "Hello there! I'm Snowy! ❄️ Do you like summer too?";
    }

    return "Oh my flurry! ❄️ I'm not sure what that means. Im just a little snowman! Maybe check our <a href='services.html' style='color:#1565C0; font-weight:bold;'>Services</a> page?";
}
});
