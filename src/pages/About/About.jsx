import { EXPERIENCE, SKILLS } from "../../data/profile"

export default function About() {
  return (
    <section className="about">
      <div className="about-intro">
        <span className="label">ABOUT</span>
        <h2>Nguyen Quang Tuan</h2>
        <p>
          AI Software Engineer from Ha Noi, working on NLP pipelines, model fine-tuning and MLOps -
          turning research into systems that run in production.
        </p>
      </div>

      <div className="about-details">
        <div className="about-block">
          <span className="label">EXPERIENCE</span>
          <ul className="timeline">
            {EXPERIENCE.map((item) => (
              <li key={item.place}>
                <div className="timeline-head">
                  <strong>{item.place}</strong>
                  <span className="label">{item.time}</span>
                </div>
                <span className="timeline-role">{item.role}</span>
                <p>{item.note}</p>
              </li>
            ))}
          </ul>
        </div>

        <div className="about-block">
          <span className="label">EDUCATION</span>
          <div className="timeline-head">
            <strong>UET – VNU Ha Noi, Computer Science</strong>
            <span className="label">2022 – 2026</span>
          </div>
          <p>GPA 3.53 / 4.0</p>
        </div>

        <div className="about-block">
          <span className="label">RESEARCH</span>
          <div className="timeline-head">
            <strong>Hybrid NLP Pipeline for Zero-shot Vietnamese Multi-Label Text Classification</strong>
            <span className="label">KSE 2026</span>
          </div>
        </div>

        <div className="about-block">
          <span className="label">SKILLS</span>
          <ul className="tags">
            {SKILLS.map((skill) => (
              <li key={skill}>{skill}</li>
            ))}
          </ul>
        </div>
      </div>
    </section>
  )
}
