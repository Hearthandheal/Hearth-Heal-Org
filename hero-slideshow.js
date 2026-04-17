// Hero Background Slideshow - Rotating Community Photos
(function() {
    const images = [
        'assets/community-bg.jpg',      // Original
        'assets/community-1.jpg',       // Photo 1
        'assets/community-2.jpg',       // Photo 2
        'assets/community-3.jpg',       // Photo 3
        'assets/community-4.jpg',       // Photo 4
        'assets/community-5.jpg',       // Photo 5
        'assets/community-6.jpg',       // New - speaking
        'assets/community-7.jpg',       // New - group circle
        'assets/community-8.jpg',       // New - podcast shirt
        'assets/community-9.jpg',       // New - speaking to group
        'assets/community-10.jpg'       // New - wide circle
    ];

    let currentIndex = 0;
    const hero = document.querySelector('.hero');
    
    if (!hero) return;

    // Preload images
    images.forEach(src => {
        const img = new Image();
        img.src = src;
    });

    // Create slideshow layers
    const slideshowContainer = document.createElement('div');
    slideshowContainer.className = 'hero-slideshow';
    slideshowContainer.innerHTML = `
        <div class="slide active" style="background-image: url('${images[0]}')"></div>
        <div class="slide next" style="background-image: url('${images[1]}')"></div>
    `;
    
    // Insert before hero content
    hero.insertBefore(slideshowContainer, hero.firstChild);

    // Rotation function
    function rotateSlide() {
        const slides = slideshowContainer.querySelectorAll('.slide');
        const active = slides[0];
        const next = slides[1];

        // Update indices
        currentIndex = (currentIndex + 1) % images.length;
        const nextIndex = (currentIndex + 1) % images.length;

        // Crossfade
        active.classList.remove('active');
        active.classList.add('fade-out');
        
        next.classList.remove('next');
        next.classList.add('active');

        // Create new next slide
        setTimeout(() => {
            const newSlide = document.createElement('div');
            newSlide.className = 'slide next';
            newSlide.style.backgroundImage = `url('${images[nextIndex]}')`;
            slideshowContainer.appendChild(newSlide);
            
            // Remove old slide
            if (slides.length > 2) {
                slides[0].remove();
            }
        }, 1000);
    }

    // Rotate every 6 seconds
    setInterval(rotateSlide, 6000);
})();
