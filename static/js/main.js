function loadProductFacts() {

  var $imageBox = $('#img-box');
  var $productBox = $('#product-box');
  var $ingredientTable = $('#ingredient-tbl-body')

  // Integrate https://world.openfoodfacts.org to retrieve product related data
  var API_JSON_URL = "http://world.openfoodfacts.org/api/v0/product/"

  // clear out old data before new request
  //$imageBox.text("");
  //$productBox.text("");
  //$ingredientTable.text("");

  // Retrieve barcode # from form
  var barcode = $("#barcode").val();

  console.log(barcode);

  $.getJSON(API_JSON_URL+barcode+".json", function( data ) {
    name = data.product.product_name; //Access the attribute docs from the response object and stores it in the variable articles
    ingredients = data.product.ingredients_tags

    $imageBox.append(
      '<img src="'+data.product.image_front_small_url+'" class="img-fluid" alt="">'
    );

    $productBox.append(
      '<h4 class="card-title">'+name+'</h4>'
    );

    $.each(ingredients, function(key, value) {  //articles contain objects with attributes, so value is an actual object
      $ingredientTable.append(
        '<tr><td>'+value+'</td><td>?</td><td>?</td></tr>'
      );
    });

  }).fail(function(e) {
    $nytHeaderElem.text('Can not retrieve data from openfoodfacts.org');
  });

};

// Functions for the SHOPPING LIST (sl)
