const features = [
  ['Fast by design', 'Pages load instantly and stay responsive, whatever the load.'],
  ['Secure by default', 'Built with privacy and reliability as first principles.'],
  ['Simple to use', 'A clean, focused experience with nothing in your way.'],
]

export default function App() {
  return (
    <>
      <nav><b>Northwind</b><div><a href="#features">Features</a><a href="#about">About</a><a href="#contact">Contact</a></div></nav>
      <header className="hero">
        <h1>Build something people love.</h1>
        <p>A modern, reliable platform that stays out of your way and keeps everything running smoothly.</p>
        <a className="btn" href="#contact">Get started</a>
      </header>
      <section id="features" className="cards">
        {features.map(([t, d]) => <div className="card" key={t}><h3>{t}</h3><p>{d}</p></div>)}
      </section>
      <section id="about" className="about"><h2>About us</h2>
        <p>We are a small team focused on crafting dependable software with thoughtful design. Our goal is simple: make great tools that just work.</p></section>
      <section id="contact" className="about"><h2>Contact</h2>
        <p>Questions? Write to <a href="mailto:hello@example.com">hello@example.com</a>.</p></section>
      <footer>© 2026 Northwind. All rights reserved.</footer>
    </>
  )
}
