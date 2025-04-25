import os
import openai
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import PP_ALIGN
from dotenv import load_dotenv
import requests
from io import BytesIO
from flask import url_for
import json
import logging
import re

load_dotenv()
openai.api_key = os.getenv('OPENAI_API_KEY')

# Set up logging
logging.basicConfig(level=logging.INFO)

COLOR_THEMES = {
    'blue': RGBColor(0, 112, 192),
    'green': RGBColor(0, 176, 80),
    'red': RGBColor(192, 0, 0),
    'gray': RGBColor(128, 128, 128),
    'blue_white_gradient': (RGBColor(0, 112, 192), RGBColor(255, 255, 255)),
    'red_gray_gradient': (RGBColor(192, 0, 0), RGBColor(128, 128, 128)),
}

def generate_slides_content(topic, num_slides):
    prompt = f"""
    Generate {num_slides} PowerPoint slides about '{topic}'.
    For each slide, respond in JSON as an array of objects with:
    - title
    - bullets (3-5 bullet points)
    - image_prompt (short description for DALL·E 3)
    """
    try:
        response = openai.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=1200,
            temperature=0.7
        )
        slides = json.loads(response.choices[0].message.content)
        return slides
    except openai.RateLimitError:
        logging.error("OpenAI API rate limit exceeded or insufficient quota")
        raise Exception("API quota exceeded. Please try again later or check your billing status.")
    except openai.APIError as e:
        logging.error(f"OpenAI API error: {str(e)}")
        raise Exception("Unable to generate slides content. Please try again later.")
    except Exception as e:
        logging.error(f"Unexpected error in generate_slides_content: {str(e)}")
        raise Exception("An unexpected error occurred. Please try again later.")

def generate_slide_images(slides, user_tier):
    images = []
    for slide in slides:
        prompt = slide['image_prompt']
        try:
            dalle_response = openai.images.generate(
                model="dall-e-3",
                prompt=prompt,
                n=1,
                size="1024x1024"
            )
            image_url = dalle_response.data[0].url
            logging.info(f"DALL·E image URL for '{slide['title']}': {image_url}")
            img_data = requests.get(image_url).content
            img_path = os.path.join('static', 'presentations', f"{slide['title'][:10]}_img.png")
            with open(img_path, 'wb') as f:
                f.write(img_data)
            images.append(img_path)
        except openai.RateLimitError:
            logging.error(f"OpenAI API rate limit exceeded for image generation: {slide['title']}")
            images.append(None)
        except Exception as e:
            logging.error(f"Failed to generate or save image for slide '{slide['title']}': {e}")
            images.append(None)
    return images

def create_pptx(slides, images, color_theme, output_path, user_tier):
    prs = Presentation()
    theme = COLOR_THEMES.get(color_theme, RGBColor(0, 112, 192))
    
    # Slide dimensions and spacing constants (in inches)
    SLIDE_WIDTH = 10
    SLIDE_HEIGHT = 7.5
    MARGIN = 0.5
    TITLE_HEIGHT = 1.0
    MIN_PADDING = 1.0
    
    for i, slide_data in enumerate(slides):
        slide = prs.slides.add_slide(prs.slide_layouts[5])
        
        # Set background color or gradient
        fill = slide.background.fill
        if color_theme.endswith('_gradient'):
            fill.gradient()
            fill.gradient_stops[0].color.rgb = theme[0]
            fill.gradient_stops[1].color.rgb = theme[1]
        else:
            fill.solid()
            fill.fore_color.rgb = theme

        # Title placement with consistent margins
        title_text = slide_data['title']
        title_text = re.sub(r"^Slide\s*\d+[:\-\.]?\s*", "", title_text)
        title_box = slide.shapes.add_textbox(
            Inches(MARGIN), 
            Inches(MARGIN),
            Inches(SLIDE_WIDTH - 2*MARGIN), 
            Inches(TITLE_HEIGHT)
        )
        title_frame = title_box.text_frame
        title_frame.text = title_text
        title_frame.paragraphs[0].font.size = Pt(32)
        title_frame.paragraphs[0].font.bold = True
        
        # Calculate content height based on number of bullet points
        # Estimate 0.4 inches per bullet point plus padding
        content_height = len(slide_data['bullets']) * 0.4 + 0.3
        total_content_height = TITLE_HEIGHT + content_height + MARGIN
        
        # Determine layout based on content height
        if total_content_height > SLIDE_HEIGHT * 0.5:
            # Vertical layout (text above, image below)
            text_width = SLIDE_WIDTH - 2*MARGIN
            text_left = MARGIN
            text_top = TITLE_HEIGHT + MARGIN
            
            # Center image below text
            image_width = min(5.0, SLIDE_WIDTH - 4*MARGIN)  # Max 5 inches wide
            image_height = min(3.0, SLIDE_HEIGHT - total_content_height - 2*MARGIN)
            image_left = (SLIDE_WIDTH - image_width) / 2
            image_top = text_top + content_height + MARGIN
        else:
            # Horizontal layout (text left, image right)
            text_width = (SLIDE_WIDTH - 3*MARGIN) * 0.5  # Use half width for text
            text_left = MARGIN
            text_top = TITLE_HEIGHT + MARGIN
            
            # Place image to the right with padding
            image_width = SLIDE_WIDTH - text_width - 3*MARGIN
            image_height = 4.0  # Fixed height for horizontal layout
            image_left = text_width + 2*MARGIN
            image_top = text_top
        
        # Add bullet points
        bullet_box = slide.shapes.add_textbox(
            Inches(text_left),
            Inches(text_top),
            Inches(text_width),
            Inches(content_height)
        )
        bullet_frame = bullet_box.text_frame
        bullet_frame.word_wrap = True
        
        for bullet in slide_data['bullets']:
            p = bullet_frame.add_paragraph()
            p.text = bullet
            p.font.size = Pt(20)
            p.level = 0
            p.space_after = Pt(12)  # Add spacing between bullets
        
        # Add image with calculated dimensions
        if images and len(images) > i and images[i]:
            try:
                img_shape = slide.shapes.add_picture(
                    images[i],
                    Inches(image_left),
                    Inches(image_top),
                    Inches(image_width),
                    Inches(image_height)
                )
                
                # Maintain aspect ratio
                aspect_ratio = img_shape.height / img_shape.width
                new_width = min(image_width, image_height / aspect_ratio)
                new_height = new_width * aspect_ratio
                
                # Recenter image in its allocated space
                x_offset = (image_width - new_width) / 2
                img_shape.left = Inches(image_left + x_offset)
                img_shape.width = Inches(new_width)
                img_shape.height = Inches(new_height)
                
            except Exception as e:
                logging.error(f"Failed to add image to slide '{title_text}': {e}")
        
        # Watermark for free users (at bottom of slide)
        if user_tier == 'free':
            watermark_box = slide.shapes.add_textbox(
                Inches(MARGIN),
                Inches(SLIDE_HEIGHT - 0.7),
                Inches(SLIDE_WIDTH - 2*MARGIN),
                Inches(0.4)
            )
            watermark_frame = watermark_box.text_frame
            watermark_frame.text = "Generated by Decklyst (Free)"
            watermark_frame.paragraphs[0].font.size = Pt(14)
            watermark_frame.paragraphs[0].font.color.rgb = RGBColor(180, 180, 180)
            watermark_frame.paragraphs[0].alignment = PP_ALIGN.CENTER
    
    prs.save(output_path)
